from types import SimpleNamespace

from src.agent.agentic_investigation_loop import InvestigationPlannerExecutorReflector
from src.agent.investigation_completeness import InvestigationCompletenessGate
from src.web.data_provider import WebDataProvider


def _state():
    return SimpleNamespace(
        session_id="sess-runtime",
        goal="Sysmon Event ID 1 stage2.exe spawned powershell.exe with encoded command",
        step_count=1,
        findings=[{"type": "tool_result", "tool": "search_logs", "summary": "Sysmon process event stage2.exe -> powershell.exe user=ACME\\alice host=WIN-1 utc timestamp"}],
        reasoning_state={"input_type": "raw_log", "objective_contract": {"lane": "log_investigation"}},
    )


def test_planner_executor_reflector_snapshot_exposes_progress_and_gaps():
    snapshot = InvestigationPlannerExecutorReflector().plan(_state(), "Verdict: malicious").to_dict()

    assert snapshot["schema_version"] == "planner-executor-reflector-result/v1"
    assert snapshot["completion"]["allowed"] is False
    assert snapshot["reflection"]["missing_milestones"]
    action_types = {item["action_type"] for item in snapshot["planned_actions"]}
    assert "pivot_network" in action_types
    assert "assess_scope" in action_types


def test_completion_gate_uses_plan_contract_action_types():
    decision = InvestigationCompletenessGate().evaluate(_state(), "No findings; clean")

    assert decision.allowed is False
    pending_types = {item.action_type for item in decision.pending_actions}
    assert {"pivot_network", "pivot_file_registry", "assess_scope"} <= pending_types
    assert any("No-findings" in reason for reason in decision.blocking_reasons)


def test_web_data_provider_extracts_investigation_progress_from_session_metadata():
    provider = WebDataProvider({})
    session = {
        "id": "sess-runtime",
        "metadata": {
            "reasoning_state": {
                "investigation_telemetry": {
                    "metrics": {"investigation_final_blocked_total": 2},
                    "latest_progress": {
                        "completion_status": "blocked_incomplete",
                        "missing_milestones": ["network"],
                        "pending_required_actions": [{"action_type": "pivot_network"}],
                    },
                }
            }
        },
    }

    progress = provider.investigation_progress_from_session(session)

    assert progress["completion_status"] == "blocked_incomplete"
    assert progress["open_gaps"] == ["network"]
    assert progress["pending_required_actions"][0]["action_type"] == "pivot_network"
    assert progress["metrics"]["investigation_final_blocked_total"] == 2
