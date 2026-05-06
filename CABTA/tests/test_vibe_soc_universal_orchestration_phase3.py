import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState
from src.agent.next_action_planner import NextActionPlanner
from src.agent.prompt_composer import PromptComposer


class _ToolLookup:
    def __init__(self, names):
        self.names = set(names)

    def get_tool(self, name):
        return {"name": name} if name in self.names else None


class _Store:
    def __init__(self):
        self.steps = []
        self.findings = []

    def add_step(self, *args, **kwargs):
        self.steps.append((args, kwargs))

    def update_session_findings(self, _session_id, findings):
        self.findings = list(findings)

    def get_session(self, _session_id):
        return {"metadata": {}}


def _planner(tool_names):
    lookup = _ToolLookup(tool_names)
    return NextActionPlanner(
        get_tool=lookup.get_tool,
        has_tool_result=lambda _state, _tool: False,
        guess_first_tool=lambda _goal: "investigate_ioc",
        guess_tool_params=lambda _goal: {"ioc": "8.8.8.8"},
        latest_analyst_message=lambda state: state.goal,
        latest_focus_candidate=lambda _state: "8.8.8.8",
        resolve_authoritative_outcome=lambda _state: None,
        simple_chat_has_strong_evidence=lambda _state: False,
        looks_like_artifact_submission=lambda _message: False,
        build_reasoning_search_request=lambda _state, _questions: {
            "query": "index=fortigate srcip=8.8.8.8",
            "timerange": "historical",
            "reasoning": "collect requested log evidence",
        },
    )


def test_use_capability_decision_for_log_search_resolves_to_search_logs_plan_path():
    state = SimpleNamespace(
        goal="Threat hunt historical Splunk FortiGate logs for 8.8.8.8",
        findings=[],
        reasoning_state={"objective_contract": {"summary": "hunt logs", "effective_timerange": "historical"}},
        agentic_explanation={},
        investigation_plan={
            "lane": "log_identity",
            "next_action_signals": [
                {"capability": "log.search", "capability_id": "log.search", "reason": "Need log evidence", "priority": 100}
            ],
        },
    )

    decision = _planner(["search_logs"]).reasoning_guided_next_action(state)

    assert decision["action"] == "use_capability"
    assert decision["capability_id"] == "log.search"
    assert decision["tool"] == "search_logs"
    assert decision["params"]["timerange"] == "historical"


def test_plan_signal_with_capability_and_tool_remains_backward_compatible():
    state = SimpleNamespace(
        goal="Threat hunt historical Splunk FortiGate logs for 8.8.8.8",
        findings=[],
        reasoning_state={"objective_contract": {"summary": "hunt logs", "effective_timerange": "historical"}},
        agentic_explanation={},
        investigation_plan={
            "lane": "log_identity",
            "next_action_signals": [
                {"tool": "search_logs", "capability": "log.search", "capability_id": "log.search", "reason": "Need log evidence", "priority": 100}
            ],
        },
    )

    decision = _planner(["search_logs"]).reasoning_guided_next_action(state)

    assert decision["action"] == "use_capability"
    assert decision["tool"] == "search_logs"
    assert decision["capability_id"] == "log.search"


def test_prompt_is_capability_and_evidence_first_without_universal_ioc_first_mandate():
    payload = PromptComposer().build_think_payload(
        state=SimpleNamespace(goal="Investigate suspicious IP 8.8.8.8", investigation_plan={}, agentic_explanation={}),
        tools_block="- investigate_ioc(ioc: string)\n- search_logs(query: string)",
        findings_block="(none yet)",
        response_style_block="",
        chat_decision_block="",
        reasoning_block="Reasoning status: collecting_evidence",
        profile_block="",
        workflow_block="",
        playbooks_block="",
        model_only_chat=False,
        has_native_tools=True,
    )

    prompt = payload["system_prompt"]
    assert "objective, required capability, and missing evidence first" in prompt
    assert "For IOC investigations: call investigate_ioc first" not in prompt
    assert "For log/SIEM/firewall hunts" in prompt


def test_unknown_ioc_only_request_still_routes_to_investigate_ioc_compatibility_fallback():
    loop = AgentLoop(config={}, tool_registry=SimpleNamespace(get_tool=lambda name: object()), agent_store=_Store())

    assert loop._guess_first_tool("Please check 8.8.8.8") == "investigate_ioc"


def test_agent_loop_bridges_use_capability_to_existing_use_tool_execution_path():
    calls = []

    class Tools:
        def get_tool(self, name):
            if name == "search_logs":
                return SimpleNamespace(source="local", requires_approval=False)
            return None

        async def execute_local_tool(self, name, _execution_context=None, **params):
            calls.append((name, params, _execution_context))
            return {"status": "ok", "tool": name, "params": params}

    loop = AgentLoop(config={}, tool_registry=Tools(), agent_store=_Store())
    state = AgentState(session_id="s1", goal="Threat hunt Splunk logs", max_steps=1)
    state.reasoning_state = {"objective_contract": {"summary": "Threat hunt Splunk logs", "effective_timerange": "historical"}}

    bridged = loop._bridge_capability_decision(
        state,
        {"action": "use_capability", "capability": "log.search", "params": {"query": "index=*", "timerange": "historical"}},
    )
    result = asyncio.run(loop._act(state, bridged))

    assert bridged["action"] == "use_tool"
    assert bridged["tool"] == "search_logs"
    assert calls[0][0] == "search_logs"
    assert result["status"] == "ok"


def test_degraded_capability_does_not_fallback_to_wrong_ioc_tool():
    loop = AgentLoop(config={}, tool_registry=SimpleNamespace(get_tool=lambda name: object() if name == "investigate_ioc" else None), agent_store=_Store())
    state = AgentState(session_id="s1", goal="Threat hunt Splunk logs", max_steps=1)
    state.reasoning_state = {"objective_contract": {"summary": "Threat hunt Splunk logs", "effective_timerange": "historical"}}

    bridged = loop._bridge_capability_decision(state, {"action": "use_capability", "capability": "log.search", "params": {}})

    assert bridged["action"] == "degraded_capability"
    assert bridged["capability_id"] == "log.search"
    assert "tool" not in bridged
