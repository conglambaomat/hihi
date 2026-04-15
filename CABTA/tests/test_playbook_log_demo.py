import asyncio
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_store import AgentStore
from src.agent.demo_log_backend import load_demo_log_dataset
from src.agent.governance_store import GovernanceStore
from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry


class LocalToolPlaybookLoop:
    """Minimal dispatcher for running local-tool-only playbook demos."""

    def __init__(self, tool_registry):
        self.tool_registry = tool_registry
        self.tool_calls = []

    async def run_tool(self, tool_name, params, execution_context=None):
        execution_context = dict(execution_context or {})
        self.tool_calls.append(
            {
                "tool_name": tool_name,
                "params": params,
                "execution_context": execution_context,
            }
        )
        return await self.tool_registry.execute_local_tool(
            tool_name,
            _execution_context=execution_context,
            **params,
        )


def _demo_config():
    return {
        "log_hunting": {
            "max_window_hours": 24 * 7,
            "max_results": 25,
            "max_queries_per_hunt": 3,
            "demo_backend": {
                "enabled": True,
                "dataset": "playbook_log_hunt",
            },
        }
    }


def test_search_logs_executes_seeded_demo_dataset(tmp_path):
    governance_store = GovernanceStore(db_path=str(tmp_path / "governance.db"))
    tool_registry = ToolRegistry()
    tool_registry.register_default_tools(
        _demo_config(),
        governance_store=governance_store,
    )

    fixture = load_demo_log_dataset("playbook_log_hunt")
    known_indicators = fixture["default_inputs"]["known_indicators"]
    ip = known_indicators["ips"][0]
    domain = known_indicators["domains"][0]

    result = asyncio.run(
        tool_registry.execute_local_tool(
            "search_logs",
            query={
                "spl": [
                    f'index=* earliest=-24h | search dest_ip="{ip}" OR src_ip="{ip}"',
                    f'index=* earliest=-24h | search url="*{domain}*" OR domain="*{domain}*"',
                ]
            },
            timerange="24h",
            _execution_context={"session_id": "demo-hunt-001", "workflow_id": "log-investigation-demo"},
        )
    )

    assert result["status"] == "executed"
    assert result["mode"] == "demo_fixture"
    assert result["dataset"] == "playbook_log_hunt"
    assert result["results_count"] == fixture["expected"]["results_count"]
    assert ip in result["suspicious_indicators"]
    assert domain in result["suspicious_indicators"]
    assert result["suspicious_files"] == fixture["expected"]["suspicious_files"]

    decisions = governance_store.list_ai_decisions(session_id="demo-hunt-001")
    assert decisions
    assert decisions[0]["decision_type"] == "log_search_execution"


def test_log_investigation_demo_playbook_runs_end_to_end(tmp_path):
    fixture = load_demo_log_dataset("playbook_log_hunt")
    agent_store = AgentStore(db_path=str(tmp_path / "agent.db"))
    governance_store = GovernanceStore(db_path=str(tmp_path / "governance.db"))
    tool_registry = ToolRegistry()
    tool_registry.register_default_tools(
        _demo_config(),
        governance_store=governance_store,
    )

    loop = LocalToolPlaybookLoop(tool_registry)
    engine = PlaybookEngine(
        agent_loop=loop,
        agent_store=agent_store,
        governance_store=governance_store,
    )

    session_id = asyncio.run(
        engine.execute(
            "log_investigation_demo",
            fixture["default_inputs"],
            wait_for_completion=True,
        )
    )

    session = agent_store.get_session(session_id)
    steps = agent_store.get_steps(session_id)
    search_step = next(step for step in steps if step.get("tool_name") == "search_logs")
    search_result = json.loads(search_step["tool_result"])
    final_step = steps[-1]

    assert session["status"] == "completed"
    assert search_result["mode"] == "demo_fixture"
    assert search_result["results_count"] == fixture["expected"]["results_count"]
    assert final_step["step_type"] == "final_answer"
    assert "matching log events" in final_step["content"]

    tool_names = [item["tool_name"] for item in loop.tool_calls]
    assert tool_names[:4] == [
        "extract_iocs",
        "generate_rules",
        "search_logs",
        "extract_iocs",
    ]
    assert "correlate_findings" in tool_names
