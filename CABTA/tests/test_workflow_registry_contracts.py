import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.workflows.registry import WorkflowRegistry


def test_validate_workflow_definition_requires_playbook_id_for_playbook_backend(tmp_path):
    registry = WorkflowRegistry(workflow_root=str(tmp_path))

    validation = registry.validate_workflow_definition(
        {
            "id": "wf-playbook",
            "name": "Playbook Workflow",
            "execution-backend": "playbook",
            "agents": ["triage"],
            "capabilities": ["ioc_investigation"],
        }
    )

    assert validation["valid"] is False
    assert any("must declare playbook-id" in issue["message"] for issue in validation["issues"])


def test_validate_workflow_definition_warns_when_dependency_contract_is_thin(tmp_path):
    registry = WorkflowRegistry(workflow_root=str(tmp_path))

    validation = registry.validate_workflow_definition(
        {
            "id": "wf-agent",
            "name": "Agent Workflow",
            "execution-backend": "agent",
        }
    )

    assert validation["valid"] is True
    warning_messages = [item["message"] for item in validation["warnings"]]
    assert "Workflow declares no required tools, servers, or features" in warning_messages
    assert "Workflow declares no explicit agents/specialists" in warning_messages
    assert "Workflow declares no capability tags" in warning_messages
    assert validation["approval_mode"] == "inherited"
    assert validation["headless_ready"] is False
    assert validation["dependency_count"] == 0


def test_describe_workflow_exposes_execution_contract(tmp_path):
    workflow_dir = tmp_path / "sample-workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / "WORKFLOW.md").write_text(
        """---
id: log-hunt
name: Log Hunt
description: Hunt suspicious infrastructure in logs
execution-backend: playbook
playbook-id: log_investigation_demo
agents:
  - triage
  - investigator
capabilities:
  - log_hunting
required-tools:
  - search_logs
required-mcp-servers:
  - splunk
required-features:
  - log_hunting
approval-mode: analyst
headless-ready: true
---

## Operating Model
- Gather evidence first
- Escalate only with evidence
""",
        encoding="utf-8",
    )

    registry = WorkflowRegistry(workflow_root=str(tmp_path))
    description = registry.describe_workflow("log-hunt")

    assert description is not None
    assert description["validation"]["valid"] is True
    assert description["execution_contract"]["multi_agent"] is True
    assert description["execution_contract"]["headless_ready"] is True
    assert description["execution_contract"]["approval_mode"] == "analyst"
    assert description["execution_contract"]["requires_playbook"] is True
    assert description["execution_contract"]["supports_headless_execution"] is False
    assert description["execution_contract"]["dependency_count"] == 3
    assert description["execution_contract"]["required_dependencies"]["tools"] == ["search_logs"]
    assert description["execution_contract"]["required_dependencies"]["mcp_servers"] == ["splunk"]
    assert description["execution_contract"]["required_dependencies"]["features"] == ["log_hunting"]
    warning_messages = [item["message"] for item in description["validation"]["warnings"]]
    assert "Headless-ready workflow still requires analyst approval checkpoints" in warning_messages


def test_validate_workflow_definition_rejects_unsupported_approval_mode(tmp_path):
    registry = WorkflowRegistry(workflow_root=str(tmp_path))

    validation = registry.validate_workflow_definition(
        {
            "id": "wf-approval",
            "name": "Approval Workflow",
            "execution-backend": "agent",
            "approval-mode": "manager",
        }
    )

    assert validation["valid"] is False
    assert any("Unsupported approval mode 'manager'" == issue["message"] for issue in validation["issues"])
