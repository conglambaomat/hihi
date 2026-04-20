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


def build_app():
    return SimpleNamespace(
        state=SimpleNamespace(
            tool_registry=StubToolRegistry(),
            mcp_client=StubMCPClient(),
            playbook_engine=StubPlaybookEngine(),
            web_provider=StubWebProvider(),
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