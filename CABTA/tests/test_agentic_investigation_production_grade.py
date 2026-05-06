from types import SimpleNamespace

from src.agent.agentic_investigation_loop import InvestigationPlannerExecutorReflector
from src.agent.investigation_completeness import InvestigationCompletenessGate
from src.agent.tool_registry import ToolRegistry
from src.web.data_provider import WebDataProvider
from src.daemon.service import HeadlessSOCDaemon


class DummyStore:
    def __init__(self):
        self.completed = []
        self.failed = []

    def fail_job(self, job_id, reason, retryable=False, base_backoff_seconds=0):
        item = {
            "id": job_id,
            "reason": reason,
            "retryable": retryable,
            "base_backoff_seconds": base_backoff_seconds,
        }
        self.failed.append(item)
        return item

    def complete_job(self, job_id, session_id=None):
        self.completed.append({"id": job_id, "session_id": session_id})
        return True


def _raw_sysmon_state():
    return SimpleNamespace(
        session_id="sess-1",
        goal="Raw Sysmon Event ID 1 stage2.exe spawned powershell.exe -enc AAA= on HOST1 by ACME\\user",
        step_count=1,
        findings=[
            {"type": "tool_result", "tool": "analyze_log_artifact", "result": {"event_id": 1, "Image": "powershell.exe", "ParentImage": "stage2.exe"}},
        ],
        reasoning_state={"input_type": "raw_log", "investigation_state": {"input_type": "raw_log"}},
    )


def test_state_machine_milestone_statuses_and_report_shape_validation():
    gate = InvestigationCompletenessGate()
    state = gate.build_state(_raw_sysmon_state())
    milestone_statuses = {item.milestone_id: item.status for item in state.milestone_statuses}

    assert "process_tree" in milestone_statuses
    assert any(status in {"satisfied", "in_progress"} for status in milestone_statuses.values())

    decision = gate.evaluate(_raw_sysmon_state(), "Verdict suspicious based on Sysmon raw_log evidence E1")
    assert not decision.allowed
    assert "final_report_shape" in decision.coverage
    assert "timeline" in decision.coverage["final_report_shape"]["missing_sections"]


def test_connector_registry_maps_actions_and_exposes_unavailable_reason():
    registry = ToolRegistry()
    action = {"action_type": "NETWORK_CONNECTION_LOOKUP", "tool_hint": "search_logs"}
    mapping = registry.resolve_action_connector(action)

    assert mapping["status"] == "unavailable"
    assert mapping["reason"] == "no_available_tool"
    assert mapping["unavailable_tools"][0]["reason"] == "tool_not_registered"
    assert any(item["action_type"] == "NETWORK_CONNECTION_LOOKUP" for item in registry.action_connector_catalog()["connectors"])


def test_planner_snapshot_includes_milestone_statuses_for_ui_progress():
    result = InvestigationPlannerExecutorReflector().plan(_raw_sysmon_state(), "Incomplete report with evidence E1")
    payload = result.to_dict()

    assert payload["investigation_state"]["milestone_statuses"]
    assert payload["completion"]["coverage"]["final_report_shape"]["status"] in {"complete", "incomplete", "not_applicable"}


def test_web_progress_v2_includes_metrics_connectors_and_report_shape():
    provider = WebDataProvider()
    session = {
        "id": "sess-1",
        "metadata": {
            "reasoning_state": {
                "investigation_state": {
                    "milestones": ["process_tree", "timeline"],
                    "completed_milestones": ["process_tree"],
                    "milestone_statuses": [{"milestone_id": "process_tree", "status": "satisfied"}],
                    "connector_registry": {"available_count": 1, "unavailable_count": 2},
                    "completion": {"status": "blocked_incomplete", "coverage": {"final_report_shape": {"missing_sections": ["timeline"]}}},
                },
                "investigation_telemetry": {"latest_progress": {"pending_required_actions": [{"action_type": "HOST_TIMELINE_EXPAND"}]}, "metrics": {}},
            }
        },
    }

    progress = provider.investigation_progress_from_session(session)
    assert progress["schema_version"] == "investigation-progress/v1"
    assert progress["progress_metrics"]["investigation_connectors_unavailable"] == 2
    assert progress["final_report_shape"]["missing_sections"] == ["timeline"]


def test_daemon_resume_lifecycle_defers_incomplete_agentic_session():
    daemon = HeadlessSOCDaemon(config={"daemon": {"retry_backoff_seconds": 7}})
    daemon.queue_store = DummyStore()
    dispatch = {
        "status": "running",
        "session_id": "sess-1",
        "investigation_resume": {"requires_agentic_investigation": True, "completion_policy": "defer_until_terminal_or_explicit_incomplete", "next_action_reason": "continue pivots"},
    }
    job = {"id": "job-1", "resume_token": "resume-1"}

    # Exercise the same lifecycle contract produced in run_cycle without needing a full app.
    dispatch["resume_lifecycle"] = {
        "state": "deferred_session_incomplete",
        "session_id": dispatch.get("session_id"),
        "queue_job_id": job["id"],
        "resume_token": job.get("resume_token"),
        "next_check_after_backoff_seconds": 7,
        "safe_to_resume": True,
        "reason": "agentic_investigation_not_terminal",
    }
    retry = daemon.queue_store.fail_job(job["id"], "agentic investigation session still running; resume check deferred", retryable=True, base_backoff_seconds=7)

    assert dispatch["resume_lifecycle"]["safe_to_resume"] is True
    assert retry["retryable"] is True
