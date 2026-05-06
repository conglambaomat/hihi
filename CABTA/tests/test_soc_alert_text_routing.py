import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from types import SimpleNamespace

from src.agent.agent_loop import AgentLoop
from src.agent.capability_actions import make_action
from src.agent.capability_plan import CapabilityPlanBuilder
from src.agent.capability_resolver import CapabilityResolver
from src.agent.next_action_planner import NextActionPlanner
from src.agent.parameter_binder import ParameterBinder
from src.agent.preflight_validator import PreflightValidator
from src.agent.coverage import CoverageEvaluator
from src.agent.llm_request_interpreter import SOCInterpretationResult
from src.agent.soc_interpretation_schema import SOCInterpretationValidationResult
from src.agent.log_query_planner import LogQueryPlanner
from src.agent.investigation_planner import InvestigationPlanner
from src.agent.request_understanding import SOCRequestInterpreter
from src.agent.universal_input_compiler import UniversalInputCompiler


EXPLICIT_SPLUNK_ALERT_TEXT = "dùng splunk để " + (
    "hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI "
    "Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM "
    "Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001."
)

ALERT_TEXT = (
    "hãy điều tra alert sau Event ID 1002 Rule Name TET-101: Detect System Information Discovery via WMI "
    "Alert Type Malware Severity Medium Alert Time Jan 11 2025, 4:21 PM Investigation Start Time Apr 29 2026, 8:49 PM "
    "Analyst N/A Alert Details System information discovery activity (Get-WmiObject -Class Win32_Bios) detected via WMI on HR-WIN-001."
)


def test_soc_alert_text_routes_to_log_investigation_not_file_analysis():
    task = SOCRequestInterpreter().interpret(ALERT_TEXT)

    assert task.intent == "alert_investigation"
    assert task.lane == "network_log_hunt"
    assert "log.search" in task.required_capabilities
    assert "file.analyze.static" not in task.required_capabilities
    assert any(entity["type"] == "host" and entity["value"] == "HR-WIN-001" for entity in task.entities)
    assert any(entity["type"] == "command_line" and "Get-WmiObject" in entity["value"] for entity in task.entities)
    assert task.timerange["source"] == "alert_time"
    assert "Jan 11 2025, 4:21 PM" in task.timerange["effective"]


def test_soc_alert_investigation_plan_preserves_log_hunt_lane():
    compiler = UniversalInputCompiler()
    compiled = compiler.compile(ALERT_TEXT)
    task = SOCRequestInterpreter().interpret(ALERT_TEXT)
    compiler.apply_to_task_state(task, compiled)

    plan = InvestigationPlanner().build_plan(ALERT_TEXT, metadata={"soc_task_state": task.to_dict(), "compiled_input": compiled.to_dict()})

    assert plan["lane"] == "host_process_log_hunt"
    assert not any(gap in {"file_hash", "file_path", "network"} for gap in plan["evidence_gaps"])
    assert all(signal.get("capability") != "file.analyze.static" for signal in plan["next_action_signals"])


def test_soc_alert_compiler_and_preflight_do_not_require_file_artifacts():
    compiler = UniversalInputCompiler()
    compiled = compiler.compile(ALERT_TEXT)
    task = SOCRequestInterpreter().interpret(ALERT_TEXT)
    compiler.apply_to_task_state(task, compiled)
    plan = CapabilityPlanBuilder().build(task, task.objective_contract)

    assert compiled.input_kind == "soc_alert_text"
    assert compiled.artifact_type == "soc_alert"
    assert task.required_capabilities[0] == "log.search"
    assert "file.analyze.static" not in task.required_capabilities
    assert all(action["capability_id"] != "file.analyze.static" for action in plan.actions)
    assert {"file.analyze.static", "email.analyze", "email.parse.inline"}.issubset(set(plan.forbidden_fallbacks))
    assert all("file.analyze.static" in action["forbidden_fallbacks"] for action in plan.actions)

    action = make_action(task, "log.search")
    binding = ParameterBinder().bind(action, task)
    decision = PreflightValidator().validate(action, binding, task)

    assert binding.missing_required == []
    assert decision.allowed is True
    assert not any("file_path_or_hash" in reason for reason in decision.blocking_reasons)
    assert decision.normalized_params["host"] == "HR-WIN-001"
    assert "Get-WmiObject -Class Win32_Bios" == decision.normalized_params["command_line"]
    assert decision.normalized_params["event_id"] == "1002"
    assert decision.normalized_params["rule_name"].startswith("TET-101")
    assert "Jan 11 2025, 4:21 PM" in decision.normalized_params["timerange"]


def _soc_alert_task_and_plan(text=ALERT_TEXT):
    compiler = UniversalInputCompiler()
    compiled = compiler.compile(text)
    task = SOCRequestInterpreter().interpret(text)
    compiler.apply_to_task_state(task, compiled)
    plan = CapabilityPlanBuilder().build(task, task.objective_contract)
    task.capability_plan = plan.to_dict()
    return task, plan


def test_soc_alert_text_blocks_legacy_file_analysis_preflight_and_resolver_summary_path():
    task, _plan = _soc_alert_task_and_plan()
    action = make_action(task, "file.analyze.static")
    binding = ParameterBinder().bind(action, task)
    decision = PreflightValidator().validate(action, binding, task)

    assert decision.allowed is False
    assert decision.clarification_required is True
    assert any("SOC alert text" in reason for reason in decision.blocking_reasons)
    assert "file_path" not in binding.params
    assert "file_path_or_hash" in binding.missing_required

    resolution = CapabilityResolver(get_tool=lambda name: object()).resolve("file.analyze.static", objective=task.objective_contract)
    assert "file_path" not in resolution.params_template
    assert "hash" not in resolution.params_template


def test_soc_alert_text_planner_skips_forbidden_file_fallback_signal():
    task, plan = _soc_alert_task_and_plan()
    state = SimpleNamespace(
        goal=ALERT_TEXT,
        findings=[],
        investigation_plan={
            "lane": "file",
            "next_action_signals": [{"capability": "file.analyze.static", "tool": "analyze_malware", "reason": "legacy malware category fallback", "priority": 100}],
        },
        reasoning_state={"soc_task_state": task.to_dict(), "capability_plan": plan.to_dict(), "compiled_input": task.compiled_input},
        agentic_explanation={},
    )
    planner = NextActionPlanner(
        get_tool=lambda name: object(),
        has_tool_result=lambda _state, _tool: False,
        guess_first_tool=lambda _text: "analyze_malware",
        guess_tool_params=lambda _text: {"file_path": ALERT_TEXT},
        latest_analyst_message=lambda _state: ALERT_TEXT,
        latest_focus_candidate=lambda _state: None,
        resolve_authoritative_outcome=lambda _state: None,
        simple_chat_has_strong_evidence=lambda _state: False,
        looks_like_artifact_submission=lambda _text: False,
        build_reasoning_search_request=lambda _state, _questions: {"query": "EventCode=1002 HR-WIN-001", "timerange": "24h", "reasoning": "alert log route"},
    )

    decision = planner.reasoning_guided_next_action(state)
    assert decision is None or decision.get("tool") != "analyze_malware"
    assert decision is None or decision.get("capability_id") != "file.analyze.static"


def test_soc_alert_text_bridge_blocks_file_analysis_without_explicit_artifact():
    task, plan = _soc_alert_task_and_plan()
    state = SimpleNamespace(
        goal=ALERT_TEXT,
        reasoning_state={"soc_task_state": task.to_dict(), "capability_plan": plan.to_dict(), "compiled_input": task.compiled_input},
    )

    blocked = AgentLoop._soc_alert_file_analysis_blocker(AgentLoop.__new__(AgentLoop), state, "file.analyze.static", {})
    assert blocked["action"] == "ask_clarification"
    assert blocked["preferred_capability"] == "log.search"

    allowed = AgentLoop._soc_alert_file_analysis_blocker(AgentLoop.__new__(AgentLoop), state, "file.analyze.static", {"hash": "a" * 64})
    assert allowed is None


class _RejectingLLMInterpreter:
    async def interpret(self, _message, _context):
        return SOCInterpretationResult(
            status="rejected",
            interpretation=None,
            validation=SOCInterpretationValidationResult(schema_status="invalid", errors=["test rejection"]),
        )


def test_explicit_splunk_wmi_alert_primary_llm_rejection_falls_back_to_log_search_not_case_context():
    import asyncio

    interpreter = SOCRequestInterpreter(llm_interpreter=_RejectingLLMInterpreter(), mode="primary")
    task = asyncio.run(interpreter.interpret_async(EXPLICIT_SPLUNK_ALERT_TEXT, {"llm_request_interpreter_mode": "primary"}))

    assert task.intent == "alert_investigation"
    assert task.lane == "network_log_hunt"
    assert "splunk" in task.requested_backends
    assert "log.search" in task.required_capabilities
    assert task.required_capabilities != ["case.context.read"]
    assert not task.pending_clarifications
    assert any(progress.get("event_type") == "llm_interpretation_rejected_explicit_log_fallback_used" for progress in task.progress_events)


def test_explicit_splunk_wmi_alert_compiles_to_host_process_coverage_not_network_certificate_contract():
    compiler = UniversalInputCompiler()
    compiled = compiler.compile(EXPLICIT_SPLUNK_ALERT_TEXT)
    task = SOCRequestInterpreter().interpret(EXPLICIT_SPLUNK_ALERT_TEXT)
    compiler.apply_to_task_state(task, compiled)

    coverage = CoverageEvaluator().evaluate(
        active_observations=[],
        entity_state={},
        evidence_state={},
        reasoning_state={"soc_task_state": task.to_dict()},
        lane=task.lane,
    )

    assert compiled.input_kind == "soc_alert_text"
    assert task.lane == "host_process_log_hunt"
    assert "log.search" in task.required_capabilities
    assert "certificate" not in coverage["coverage_targets"]
    assert "destination_ip" not in coverage["coverage_targets"]
    assert "destination_port" not in coverage["coverage_targets"]
    assert "protocol_app" not in coverage["coverage_targets"]
    assert {"host", "process", "command_line", "event_code"}.issubset(set(coverage["coverage_targets"]))


def test_explicit_splunk_wmi_alert_query_plan_emits_executable_splunk_process_pivots():
    plan = LogQueryPlanner().build_plan(
        analyst_request=EXPLICIT_SPLUNK_ALERT_TEXT,
        lane="host_process_log_hunt",
        timerange="Jan 11 2025, 4:21 PM",
    )

    splunk_queries = plan["query_bundle"].get("splunk") or []
    assert plan["validation"]["executable_query_count"] >= 1
    assert splunk_queries
    assert any("Get-WmiObject" in query for query in splunk_queries)
    assert any("HR-WIN-001" in query for query in splunk_queries)
    assert any("TET-101" in query for query in splunk_queries)
    assert "certificate" not in plan["required_facets"]
    assert "destination_ip" not in plan["required_facets"]
