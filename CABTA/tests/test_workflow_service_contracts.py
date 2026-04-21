import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.workflows.service import WorkflowService


class StubWorkflowRegistry:
    def __init__(self):
        self._workflow = {
            "id": "wf-1",
            "name": "Workflow One",
            "description": "Investigate suspicious activity",
            "execution_backend": "playbook",
            "playbook_id": "pb-1",
            "default_agent_profile": "investigator",
            "agents": ["triage", "investigator"],
            "required_tools": ["search_logs"],
            "required_mcp_servers": ["splunk"],
            "required_features": ["log_hunting"],
            "optional_mcp_servers": ["virustotal"],
            "approval_mode": "analyst",
            "headless_ready": True,
            "required_soc_lanes": ["identity", "network"],
        }

    def get_workflow(self, workflow_id):
        if workflow_id != "wf-1":
            return None
        return dict(self._workflow)

    def describe_workflow(self, workflow_id):
        workflow = self.get_workflow(workflow_id)
        if workflow is None:
            return None
        return {
            **workflow,
            "validation": {"valid": True, "issues": [], "warnings": []},
            "execution_contract": {
                "multi_agent": True,
                "headless_ready": True,
                "approval_mode": "analyst",
                "requires_playbook": True,
                "supports_headless_execution": False,
                "dependency_count": 3,
                "required_dependencies": {
                    "tools": ["search_logs"],
                    "mcp_servers": ["splunk"],
                    "features": ["log_hunting"],
                },
                "fallback_paths": [
                    "Continue with governed manual log pivots when optional servers are degraded.",
                    "Preserve deterministic verdict ownership until corroborating evidence arrives.",
                ],
                "stop_conditions": [
                    "Stop when required dependencies are blocked.",
                    "Stop when no plan signals or evidence are available.",
                ],
                "plan_contract": {
                    "required": True,
                    "planner": "InvestigationPlanner",
                    "pivot_signals_supported": True,
                    "resume_signals_supported": True,
                },
                "evidence_contract": {
                    "required": True,
                    "require_typed_observations": True,
                    "require_triage_contract_evidence": True,
                    "minimum_required_fields": 2,
                },
                "governance_contract": {
                    "contract_version": "governance-contract/v2",
                    "deterministic_verdict_owner": "CABTA deterministic core",
                    "decision_logging_supported": True,
                    "feedback_logging_supported": True,
                    "approvals_required": True,
                },
            },
        }


class StubAgentStore:
    def __init__(self):
        self._sessions = [
            {
                "id": "sess-1",
                "status": "completed",
                "case_id": "case-1",
                "created_at": "2026-04-20T00:00:00Z",
                "completed_at": "2026-04-20T00:10:00Z",
                "summary": "Done",
                "metadata": {
                    "workflow_id": "wf-1",
                    "max_steps": 6,
                    "current_step": 6,
                    "agent_profile_id": "investigator",
                    "active_specialist": "investigator",
                    "specialist_team": ["triage", "investigator"],
                    "evidence_quality_summary": {
                        "observation_count": 3,
                        "observation_lanes": {"identity": 2, "network": 1},
                    },
                    "fact_family_schemas": {"log": {"version": "fact-family/log/v1"}},
                },
            },
            {
                "id": "sess-2",
                "status": "waiting_approval",
                "case_id": "case-2",
                "created_at": "2026-04-20T01:00:00Z",
                "completed_at": None,
                "summary": "",
                "metadata": {
                    "workflow_id": "wf-1",
                    "max_steps": 6,
                    "current_step": 3,
                    "agent_profile_id": "triage",
                    "active_specialist": "triage",
                    "pending_approval": {"tool": "search_logs"},
                    "investigation_plan": {
                        "next_action_signals": [{"tool": "search_logs"}],
                        "resume_signals": [{"type": "approval_resumed"}],
                        "triage_contracts": [
                            {
                                "contract_id": "windows_logon_monitoring",
                                "required_fields": ["account", "host", "source_ip"],
                                "deterministic_verdict_owner": "CABTA deterministic core",
                            }
                        ],
                    },
                },
            },
        ]

    def list_sessions(self, limit=50, status=None):
        sessions = self._sessions
        if status:
            sessions = [item for item in sessions if item.get("status") == status]
        return sessions[:limit]

    def get_session(self, session_id):
        for item in self._sessions:
            if item["id"] == session_id:
                return item
        return None

    def get_steps(self, session_id):
        return [{"step_number": 1, "content": "stub"}]

    def list_specialist_tasks(self, session_id):
        return [{"id": f"task-{session_id}"}]


class StubToolRegistry:
    def get_tool(self, tool_name):
        return {"name": tool_name} if tool_name == "search_logs" else None


class StubMCPClient:
    def get_connection_status(self):
        return {
            "splunk": {"connected": True},
            "virustotal": {"connected": False},
        }


class StubWebProvider:
    def feature_status(self, app):
        return {"log_hunting": {"status": "available"}}


class StubPlaybookEngine:
    def get_playbook(self, playbook_id):
        return {"id": playbook_id} if playbook_id == "pb-1" else None


def build_app(governance_store=object()):
    return SimpleNamespace(
        state=SimpleNamespace(
            tool_registry=StubToolRegistry(),
            mcp_client=StubMCPClient(),
            playbook_engine=StubPlaybookEngine(),
            web_provider=StubWebProvider(),
            governance_store=governance_store,
        )
    )


def test_describe_workflow_runtime_merges_contract_dependencies_and_runs():
    service = WorkflowService(StubWorkflowRegistry(), StubAgentStore())
    payload = service.describe_workflow_runtime(build_app(), "wf-1")

    assert payload["workflow"]["id"] == "wf-1"
    assert payload["dependency_status"]["status"] == "degraded"
    assert payload["dependency_status"]["blocked"] is False
    assert payload["dependency_status"]["degraded"] is True
    assert payload["dependency_status"]["dependency_count"] == 4
    assert payload["dependency_status"]["optional_runtime"]["degraded"] is True
    assert payload["dependency_status"]["optional_runtime"]["degraded_dependencies"] == ["virustotal"]
    assert payload["dependency_status"]["optional_runtime"]["capability_scope"] == "optional_infrastructure"
    assert payload["dependency_status"]["optional_runtime"]["message"].startswith("Optional MCP infrastructure is degraded")
    assert payload["run_contract"]["supports_headless"] is True
    assert payload["run_contract"]["supports_headless_execution"] is False
    assert payload["run_contract"]["approval_mode"] == "analyst"
    assert payload["run_contract"]["execution_backend"] == "playbook"
    assert payload["run_contract"]["requires_playbook"] is True
    assert payload["run_contract"]["dependency_count"] == 3
    assert payload["run_contract"]["dependency_status_label"] == "degraded"
    assert payload["run_contract"]["is_dependency_blocked"] is False
    assert payload["run_contract"]["is_dependency_degraded"] is True
    assert payload["run_contract"]["recent_run_count"] == 2
    assert payload["run_contract"]["active_run_count"] == 1
    assert payload["run_contract"]["completed_run_count"] == 1
    assert payload["run_contract"]["fact_contract"]["contract_version"] == "workflow-runtime-contract/v2"
    assert payload["run_contract"]["fact_contract"]["typed_observation_contract"] == "observation-contract/v2"
    assert payload["run_contract"]["fact_contract"]["required_soc_lanes"] == ["identity", "network"]
    assert payload["run_contract"]["fact_contract"]["plan_driven_investigation"] is True
    assert payload["run_contract"]["fact_contract"]["plan_contract"]["planner"] == "InvestigationPlanner"
    assert payload["run_contract"]["fact_contract"]["governance_hooks"]["decision_logging_supported"] is True
    assert payload["run_contract"]["governance_hooks"]["contract_version"] == "governance-contract/v2"
    assert payload["runtime_enforcement"]["status"] == "blocked"
    assert "missing_plan_signals" in payload["runtime_enforcement"]["blocking_reasons"]
    assert "missing_triage_contract_evidence" in payload["runtime_enforcement"]["blocking_reasons"]
    assert payload["runtime_enforcement"]["fallback_contract"]["declared"] is True
    assert payload["runtime_enforcement"]["fallback_contract"]["active"] is True
    assert "missing_plan_signals" in payload["runtime_enforcement"]["stop_condition_contract"]["triggered"]
    assert payload["runtime_enforcement"]["execution_surface"] == {
        "headless_declared": True,
        "headless_ready": True,
        "supports_headless_execution": False,
        "interactive_runtime_required": True,
        "headless_blockers": ["approval_checkpoints_require_interactive_runtime"],
        "runtime_mode": "interactive_only",
        "optional_runtime_degraded": True,
        "optional_runtime_blockers": ["virustotal"],
        "dependency_status": "degraded",
        "capability_scope": "workflow_runtime_contract",
    }
    assert payload["run_contract"]["fallback_paths"][0].startswith("Continue with governed manual log pivots")
    assert "Stop when required dependencies are blocked." in payload["run_contract"]["stop_conditions"]
    assert payload["run_contract"]["is_runtime_blocked"] is True


def test_get_run_and_list_runs_expose_runtime_fields():
    service = WorkflowService(StubWorkflowRegistry(), StubAgentStore())

    runs = service.list_runs(workflow_id="wf-1")
    assert len(runs) == 2
    assert runs[0]["execution_backend"] == "playbook"
    assert runs[0]["headless_ready"] is True
    assert runs[0]["approval_mode"] == "analyst"
    assert runs[0]["requires_playbook"] is True

    detailed = service.get_run("sess-2")
    assert detailed is not None
    assert detailed["pending_approval"] == {"tool": "search_logs"}
    assert detailed["steps"] == [{"step_number": 1, "content": "stub"}]
    assert detailed["specialist_tasks"] == [{"id": "task-sess-2"}]
    assert detailed["typed_fact_contract"]["contract_version"] == "workflow-runtime-contract/v2"
    assert detailed["typed_fact_contract"]["observation_contract_version"] == "observation-contract/v2"
    assert detailed["typed_fact_contract"]["observation_count"] == 0
    assert detailed["typed_fact_contract"]["plan_driven_investigation"] is True
    assert detailed["typed_fact_contract"]["plan_has_next_action_signals"] is True
    assert detailed["typed_fact_contract"]["plan_has_resume_signals"] is True
    assert detailed["typed_fact_contract"]["governance_contract_version"] == "governance-contract/v2"

    completed = service.get_run("sess-1")
    assert completed is not None
    assert completed["typed_fact_contract"]["observation_count"] == 3
    assert completed["typed_fact_contract"]["observation_lanes"]["identity"] == 2
    assert completed["typed_fact_contract"]["fact_family_schemas"] == ["log"]
    assert detailed["runtime_contract"]["plan_signal_count"] == 2
    assert detailed["runtime_contract"]["triage_contract_count"] == 1
    assert detailed["runtime_contract"]["governed"] is True


def test_evaluate_runtime_readiness_requires_plan_evidence_and_governance_contracts():
    service = WorkflowService(StubWorkflowRegistry(), StubAgentStore())

    blocked = service.evaluate_runtime_readiness(
        build_app(governance_store=None),
        "wf-1",
        goal="",
        params={},
        metadata={},
    )

    assert blocked["status"] == "blocked"
    assert set(blocked["blocking_reasons"]) >= {
        "missing_plan",
        "missing_plan_signals",
        "missing_evidence",
        "missing_triage_contract_evidence",
        "missing_governance_store",
    }
    assert blocked["governance_contract"]["approvals_required"] is True

    ready = service.evaluate_runtime_readiness(
        build_app(),
        "wf-1",
        goal="Investigate suspicious identity activity",
        params={
            "investigation_plan": {
                "next_action_signals": [{"tool": "search_logs"}],
                "triage_contracts": [
                    {
                        "contract_id": "windows_logon_monitoring",
                        "required_fields": ["account", "host"],
                        "deterministic_verdict_owner": "CABTA deterministic core",
                    }
                ],
            },
            "typed_observations": [
                {"observation_type": "auth_event", "account": "alice", "host": "WS-12"}
            ],
        },
        metadata={},
    )

    assert ready["status"] == "degraded"
    assert ready["ready"] is True
    assert ready["plan_contract"]["signal_count"] == 1
    assert ready["evidence_contract"]["typed_observation_count"] == 1
    assert ready["evidence_contract"]["triage_contract_runtime"]["satisfied_count"] == 1
    assert ready["fallback_contract"]["declared"] is True
    assert ready["fallback_contract"]["active"] is True
    assert ready["stop_condition_contract"]["declared"] is True
    assert ready["stop_condition_contract"]["triggered"] == []
    assert ready["execution_surface"] == {
        "headless_declared": True,
        "headless_ready": True,
        "supports_headless_execution": False,
        "interactive_runtime_required": True,
        "headless_blockers": ["approval_checkpoints_require_interactive_runtime"],
        "runtime_mode": "interactive_only",
        "optional_runtime_degraded": True,
        "optional_runtime_blockers": ["virustotal"],
        "dependency_status": "degraded",
        "capability_scope": "workflow_runtime_contract",
    }
    dependency_status = service.validate_dependencies(build_app(), "wf-1")
    assert dependency_status["optional_runtime"] == {
        "degraded": True,
        "degraded_dependencies": ["virustotal"],
        "capability_scope": "optional_infrastructure",
        "message": "Optional MCP infrastructure is degraded; workflow execution can continue with governed fallback paths.",
    }