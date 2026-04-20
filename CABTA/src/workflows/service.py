"""Workflow execution helpers and dependency validation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class WorkflowService:
    """Bridge workflow definitions to existing CABTA sessions and playbooks."""

    def __init__(self, workflow_registry, agent_store, case_store=None):
        self.workflow_registry = workflow_registry
        self.agent_store = agent_store
        self.case_store = case_store

    def describe_workflow_runtime(self, app: Any, workflow_id: str) -> Dict[str, Any]:
        workflow = self.workflow_registry.get_workflow(workflow_id)
        if workflow is None:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        registry_describe = getattr(self.workflow_registry, "describe_workflow", None)
        workflow_contract = (
            registry_describe(workflow_id)
            if callable(registry_describe)
            else dict(workflow)
        )
        dependency_status = self.validate_dependencies(app, workflow_id)

        runs = self.list_runs(limit=20, workflow_id=workflow_id)
        recent_statuses = [run.get("status") for run in runs if run.get("status")]
        active_runs = sum(1 for status in recent_statuses if status in {"active", "running", "waiting_approval"})
        completed_runs = sum(1 for status in recent_statuses if status == "completed")

        execution_contract = workflow_contract.get("execution_contract", {}) if isinstance(workflow_contract, dict) else {}

        return {
            "workflow": workflow_contract,
            "dependency_status": dependency_status,
            "run_contract": {
                "supports_headless": bool(workflow.get("headless_ready")),
                "supports_headless_execution": bool(
                    execution_contract.get(
                        "supports_headless_execution",
                        workflow.get("headless_ready") and workflow.get("approval_mode", "inherited") != "analyst",
                    )
                ),
                "approval_mode": workflow.get("approval_mode", "inherited"),
                "execution_backend": workflow.get("execution_backend", "agent"),
                "requires_playbook": bool(workflow.get("playbook_id")),
                "dependency_count": int(
                    execution_contract.get(
                        "dependency_count",
                        len(workflow.get("required_tools", []))
                        + len(workflow.get("required_mcp_servers", []))
                        + len(workflow.get("required_features", [])),
                    )
                ),
                "dependency_status_label": dependency_status.get("status", "unknown"),
                "is_dependency_blocked": dependency_status.get("status") == "blocked",
                "is_dependency_degraded": dependency_status.get("status") == "degraded",
                "recent_run_count": len(runs),
                "active_run_count": active_runs,
                "completed_run_count": completed_runs,
                "recent_statuses": recent_statuses[:10],
            },
        }

    def validate_dependencies(self, app: Any, workflow_id: str) -> Dict[str, Any]:
        workflow = self.workflow_registry.get_workflow(workflow_id)
        if workflow is None:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        tool_registry = getattr(app.state, "tool_registry", None)
        mcp_client = getattr(app.state, "mcp_client", None)
        playbook_engine = getattr(app.state, "playbook_engine", None)
        provider = getattr(app.state, "web_provider", None)
        feature_status = provider.feature_status(app) if provider else {}
        mcp_status = mcp_client.get_connection_status() if mcp_client else {}

        missing_required_tools = []
        available_required_tools = []
        for tool_name in workflow.get("required_tools", []):
            if tool_registry and tool_registry.get_tool(tool_name):
                available_required_tools.append(tool_name)
            else:
                missing_required_tools.append(tool_name)

        missing_required_servers = []
        connected_required_servers = []
        for server_name in workflow.get("required_mcp_servers", []):
            if mcp_status.get(server_name, {}).get("connected"):
                connected_required_servers.append(server_name)
            else:
                missing_required_servers.append(server_name)

        missing_features = []
        ready_features = []
        for feature_name in workflow.get("required_features", []):
            meta = feature_status.get(feature_name, {})
            if meta.get("status") in {"available", "configured", "enabled"}:
                ready_features.append(feature_name)
            else:
                missing_features.append(feature_name)

        optional_servers = [
            {
                "name": server_name,
                "connected": bool(mcp_status.get(server_name, {}).get("connected")),
            }
            for server_name in workflow.get("optional_mcp_servers", [])
        ]

        playbook_dependency = None
        if str(workflow.get("execution_backend") or "agent").lower() == "playbook":
            playbook_id = workflow.get("playbook_id")
            playbook_available = bool(
                playbook_id and playbook_engine is not None and playbook_engine.get_playbook(playbook_id)
            )
            playbook_dependency = {
                "id": playbook_id,
                "available": playbook_available,
            }

        if (
            missing_required_tools
            or missing_required_servers
            or missing_features
            or (playbook_dependency is not None and not playbook_dependency["available"])
        ):
            status = "blocked"
        elif any(not item["connected"] for item in optional_servers):
            status = "degraded"
        else:
            status = "ready"

        return {
            "workflow_id": workflow_id,
            "status": status,
            "blocked": status == "blocked",
            "degraded": status == "degraded",
            "dependency_count": len(workflow.get("required_tools", []))
            + len(workflow.get("required_mcp_servers", []))
            + len(workflow.get("required_features", []))
            + (1 if playbook_dependency is not None else 0),
            "required_tools": {
                "available": available_required_tools,
                "missing": missing_required_tools,
            },
            "required_mcp_servers": {
                "connected": connected_required_servers,
                "missing": missing_required_servers,
            },
            "required_features": {
                "ready": ready_features,
                "missing": missing_features,
            },
            "optional_mcp_servers": optional_servers,
            "required_playbook": playbook_dependency,
        }

    def list_runs(
        self,
        *,
        limit: int = 50,
        status: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sessions = self.agent_store.list_sessions(limit=limit, status=status)
        results = []
        for session in sessions:
            metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
            resolved_workflow_id = metadata.get("workflow_id")
            if not resolved_workflow_id:
                continue
            if workflow_id and workflow_id != resolved_workflow_id:
                continue
            results.append(self._build_run_summary(session))
        return results

    def get_run(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.agent_store.get_session(session_id)
        if session is None:
            return None
        metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
        if not metadata.get("workflow_id"):
            return None
        payload = self._build_run_summary(session)
        payload["steps"] = self.agent_store.get_steps(session_id)
        payload["specialist_tasks"] = self.agent_store.list_specialist_tasks(session_id)
        return payload

    def _build_run_summary(self, session: Dict[str, Any]) -> Dict[str, Any]:
        metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
        workflow_id = metadata.get("workflow_id")
        workflow = self.workflow_registry.get_workflow(workflow_id) or {}
        phases = list(metadata.get("specialist_team") or workflow.get("agents") or ["triage", "investigation", "reporting"])
        max_steps = int(metadata.get("max_steps") or len(phases) or 1)
        current_step = int(metadata.get("current_step") or 0)
        phase_index = min(int((current_step / max(max_steps, 1)) * len(phases)), max(len(phases) - 1, 0)) if phases else 0
        current_phase = metadata.get("active_specialist") or (phases[phase_index] if phases else "workflow")
        return {
            "session_id": session["id"],
            "workflow_id": workflow_id,
            "workflow_name": workflow.get("name", workflow_id),
            "status": session.get("status"),
            "case_id": session.get("case_id"),
            "agent_profile_id": metadata.get("active_specialist") or metadata.get("agent_profile_id") or workflow.get("default_agent_profile"),
            "lead_agent_profile_id": metadata.get("lead_agent_profile_id") or workflow.get("default_agent_profile"),
            "active_specialist": metadata.get("active_specialist") or current_phase,
            "specialist_team": phases,
            "specialist_count": len(phases),
            "collaboration_mode": metadata.get("collaboration_mode") or ("multi_agent" if len(phases) > 1 else "single_agent"),
            "specialist_handoffs": list(metadata.get("specialist_handoffs") or []),
            "specialist_task_count": len(self.agent_store.list_specialist_tasks(session["id"])),
            "current_step": current_step,
            "max_steps": max_steps,
            "current_phase": current_phase,
            "phase_index": phase_index,
            "phases": phases,
            "execution_backend": workflow.get("execution_backend", "agent"),
            "headless_ready": bool(workflow.get("headless_ready")),
            "approval_mode": workflow.get("approval_mode", "inherited"),
            "requires_playbook": bool(workflow.get("playbook_id")),
            "created_at": session.get("created_at"),
            "completed_at": session.get("completed_at"),
            "summary": session.get("summary"),
            "pending_approval": metadata.get("pending_approval"),
        }
