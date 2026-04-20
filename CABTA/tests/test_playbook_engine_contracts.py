import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine


class NoopLoop:
    async def run_tool(self, tool_name, params, execution_context=None):
        return {"status": "ok", "tool": tool_name, "params": params}


def build_engine(tmp_path):
    store = AgentStore(db_path=str(tmp_path / "agent.db"))
    return PlaybookEngine(agent_loop=NoopLoop(), agent_store=store)


def test_validate_playbook_definition_reports_unknown_branch_targets(tmp_path):
    engine = build_engine(tmp_path)

    validation = engine.validate_playbook_definition(
        {
            "id": "invalid-branch",
            "steps": [
                {
                    "name": "start",
                    "tool": "extract_iocs",
                    "on_success": "missing-step",
                }
            ],
        }
    )

    assert validation["valid"] is False
    assert any("unknown step 'missing-step'" in issue["message"] for issue in validation["issues"])


def test_validate_playbook_definition_reports_duplicate_steps(tmp_path):
    engine = build_engine(tmp_path)

    validation = engine.validate_playbook_definition(
        {
            "id": "dup-steps",
            "steps": [
                {"name": "repeat", "tool": "extract_iocs"},
                {"name": "repeat", "tool": "generate_rules"},
            ],
        }
    )

    assert validation["valid"] is False
    assert any("Duplicate step name: repeat" == issue["message"] for issue in validation["issues"])


def test_describe_playbook_exposes_execution_contract(tmp_path):
    engine = build_engine(tmp_path)
    playbook_id = engine.register_playbook(
        name="Contract Demo",
        description="Inspection-friendly playbook",
        steps=[
            {
                "name": "collect",
                "tool": "extract_iocs",
                "description": "Collect IOCs",
                "timeout": 45,
                "on_success": "approve_search",
            },
            {
                "name": "approve_search",
                "tool": "search_logs",
                "requires_approval": True,
                "description": "Approve log search",
                "timeout": 90,
                "on_success": "fanout_lookup",
            },
            {
                "name": "fanout_lookup",
                "tool": "lookup_indicator",
                "for_each": "iocs",
                "description": "Iterate indicators",
                "timeout": 30,
                "on_success": "summarize",
            },
            {
                "name": "summarize",
                "action": "final_answer",
                "description": "Done",
                "timeout": 15,
            },
        ],
    )

    description = engine.describe_playbook(playbook_id)

    assert description is not None
    assert description["validation"]["valid"] is True
    assert description["execution_contract"]["approval_steps"] == ["approve_search"]
    assert description["execution_contract"]["loop_steps"] == ["fanout_lookup"]
    assert description["execution_contract"]["terminal_actions"] == ["summarize"]
    assert description["execution_contract"]["supports_resume_approval"] is True
    assert description["execution_contract"]["supports_iteration"] is True
    assert description["execution_contract"]["max_timeout_seconds"] == 90
    assert description["execution_contract"]["timeout_steps"] == [
        {"name": "collect", "timeout": 45},
        {"name": "approve_search", "timeout": 90},
        {"name": "fanout_lookup", "timeout": 30},
        {"name": "summarize", "timeout": 15},
    ]
    assert description["execution_contract"]["branch_edges"] == [
        {"from": "collect", "to": "approve_search", "type": "on_success"},
        {"from": "approve_search", "to": "fanout_lookup", "type": "on_success"},
        {"from": "fanout_lookup", "to": "summarize", "type": "on_success"},
    ]
    assert "extract_iocs" in description["validation"]["declared_tools"]
    assert "search_logs" in description["validation"]["declared_tools"]
    assert "lookup_indicator" in description["validation"]["declared_tools"]


def test_load_playbook_returns_validation_error_for_invalid_yaml(tmp_path):
    engine = build_engine(tmp_path)
    playbook_path = tmp_path / "broken_playbook.yaml"
    playbook_path.write_text(
        """
id: broken-playbook
name: Broken
steps:
  - name: first
    tool: extract_iocs
    on_success: does-not-exist
""".strip(),
        encoding="utf-8",
    )

    result = engine.load_playbook(str(playbook_path))

    assert "error" in result
    assert "unknown step 'does-not-exist'" in result["error"]
    assert result["validation"]["valid"] is False


def test_validate_playbook_definition_rejects_non_positive_timeout(tmp_path):
    engine = build_engine(tmp_path)

    validation = engine.validate_playbook_definition(
        {
            "id": "bad-timeout",
            "steps": [
                {
                    "name": "collect",
                    "tool": "extract_iocs",
                    "timeout": 0,
                }
            ],
        }
    )

    assert validation["valid"] is False
    assert any("timeout must be greater than 0 seconds" == issue["message"] for issue in validation["issues"])
    assert validation["timeout_steps"] == [{"name": "collect", "timeout": 0}]
    assert validation["max_timeout_seconds"] == 0
