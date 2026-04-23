import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_loop import AgentLoop


def _build_agent_loop():
    tool_registry = MagicMock()
    tool_registry.get_tools_for_llm.return_value = [
        {"function": {"name": "investigate_ioc", "description": "Investigate IOC", "parameters": {}}}
    ]
    tool_registry.list_tools.return_value = []
    tool_registry.get_tool.return_value = object()

    agent_store = MagicMock()
    agent_store.get_session.return_value = {"metadata": {}}

    loop = AgentLoop(
        config={"llm": {"provider": "openrouter", "auto_failover": False}, "agent": {}},
        tool_registry=tool_registry,
        agent_store=agent_store,
    )
    return loop


def _build_state():
    return SimpleNamespace(
        session_id="sess-1",
        goal="Investigate suspicious IP 8.8.8.8",
        findings=[],
        reasoning_state={},
        investigation_plan={},
        active_observations=[],
        accepted_facts=[],
        unresolved_questions=[],
        entity_state={},
        agentic_explanation={},
    )


async def _raw_response(*args, **kwargs):
    return {"action": "final_answer", "answer": "done", "verdict": "UNKNOWN", "reasoning": "test"}


def test_chat_with_tools_via_provider_passes_prompt_envelope_and_model_only_chat_metadata():
    import asyncio

    loop = _build_agent_loop()
    captured = {}

    def build_chat_request(**kwargs):
        captured.update(kwargs)
        return {
            "provider": kwargs["provider_name"],
            "messages": kwargs["messages"],
            "tools": kwargs["tools_json"],
            "mode": "direct_answer" if kwargs["model_only_chat"] else "tool_decision",
            "intent": "direct_answer" if kwargs["model_only_chat"] else "tool_decision",
            "tool_choice_allowed": not kwargs["model_only_chat"] and bool(kwargs["tools_json"]),
            "native_tooling": not kwargs["model_only_chat"] and bool(kwargs["tools_json"]),
            "prompt_envelope": kwargs.get("prompt_envelope") or {},
            "prompt_mode": "direct_answer",
            "structured_intent": "direct_answer",
            "message_count": len(kwargs["messages"]),
            "tool_count": len(kwargs["tools_json"]),
        }

    loop.provider_chat_gateway.build_chat_request = MagicMock(side_effect=build_chat_request)
    loop.provider_chat_gateway.extract_chat_messages = MagicMock(return_value=[{"role": "user", "content": "hello"}])
    loop.provider_chat_gateway.extract_chat_tools = MagicMock(return_value=[])
    loop._openrouter_chat = AsyncMock(return_value="ok")

    asyncio.run(
        loop._chat_with_tools_via_provider(
            "openrouter",
            [{"role": "user", "content": "hello"}],
            [],
            {
                "model_only_chat": True,
                "prompt_envelope": {
                    "user_intent": {"mode": "direct_answer"},
                    "investigation_context": {"prompt_mode": "direct_answer"},
                },
            },
        )
    )

    assert captured["provider_name"] == "openrouter"
    assert captured["model_only_chat"] is True
    assert captured["prompt_envelope"] == {
        "user_intent": {"mode": "direct_answer"},
        "investigation_context": {"prompt_mode": "direct_answer"},
    }


def test_think_passes_prompt_metadata_into_chat_with_tools():
    import asyncio

    loop = _build_agent_loop()
    state = _build_state()

    loop._build_tools_block = MagicMock(return_value="- investigate_ioc(ioc: string)")
    loop._build_findings_block = MagicMock(return_value="(none yet)")
    loop._build_response_style_block = MagicMock(return_value="")
    loop._build_chat_decision_block = MagicMock(return_value="")
    loop._build_reasoning_block = MagicMock(return_value="Reasoning status: collecting_evidence")
    loop._build_profile_block = MagicMock(return_value="")
    loop._build_workflow_block = MagicMock(return_value="")
    loop._build_playbooks_block = MagicMock(return_value="")
    loop._filter_tools_for_goal = MagicMock(
        return_value=[{"function": {"name": "investigate_ioc", "description": "Investigate IOC", "parameters": {}}}]
    )
    loop._chat_should_force_model_answer_without_tools = MagicMock(return_value=False)
    loop._provider_prefers_json_decision_mode = MagicMock(return_value=False)
    loop._sanitize_llm_tool_decision = MagicMock(
        side_effect=lambda _state, decision, allowed_tool_names: decision
    )

    loop.prompt_composer.build_think_payload = MagicMock(
        return_value={
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}],
            "prompt_mode": "native_tooling",
            "provider_context_block": "Active specialist: triage",
            "prompt_envelope": {
                "user_intent": {"mode": "native_tooling"},
                "investigation_context": {"prompt_mode": "native_tooling"},
            },
            "model_only_chat": False,
            "uses_native_tools": True,
        }
    )

    captured = {}

    async def chat_with_tools(messages, tools_json=None, request_metadata=None):
        captured["messages"] = messages
        captured["tools_json"] = tools_json
        captured["request_metadata"] = request_metadata
        return {
            "action": "final_answer",
            "answer": "done",
            "verdict": "UNKNOWN",
            "reasoning": "test",
        }

    loop._chat_short_circuit_decision = MagicMock(return_value=None)
    loop._chat_with_tools = chat_with_tools

    result = asyncio.run(loop._think(state))

    assert result["action"] == "final_answer"
    assert captured["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}]
    assert captured["tools_json"] == [
        {"function": {"name": "investigate_ioc", "description": "Investigate IOC", "parameters": {}}}
    ]
    assert captured["request_metadata"] == {
        "prompt_mode": "native_tooling",
        "provider_context_block": "Active specialist: triage",
        "prompt_envelope": {
            "user_intent": {"mode": "native_tooling"},
            "investigation_context": {"prompt_mode": "native_tooling"},
        },
        "model_only_chat": False,
        "uses_native_tools": True,
        "planned_next_step_summary": "",
    }


def test_response_builder_metadata_helper_includes_planned_step_summary():
    loop = _build_agent_loop()

    result = loop.session_response_builder.build_think_request_metadata(
        prompt_payload={
            "prompt_mode": "native_tooling",
            "provider_context_block": "Active specialist: triage",
            "prompt_envelope": {
                "user_intent": {"mode": "native_tooling"},
                "investigation_context": {"prompt_mode": "native_tooling"},
            },
            "model_only_chat": False,
            "uses_native_tools": True,
        },
        planned_decision={
            "action": "use_tool",
            "tool": "search_logs",
            "decision_source": "telemetry_gap_log_pivot",
        },
    )

    assert result == {
        "prompt_mode": "native_tooling",
        "provider_context_block": "Active specialist: triage",
        "prompt_envelope": {
            "user_intent": {"mode": "native_tooling"},
            "investigation_context": {"prompt_mode": "native_tooling"},
        },
        "model_only_chat": False,
        "uses_native_tools": True,
        "planned_next_step_summary": "Next planned step: search_logs. Source: telemetry_gap_log_pivot.",
    }


def test_think_short_circuits_planned_chat_tool_without_prompt_round_trip():
    import asyncio

    loop = _build_agent_loop()
    state = _build_state()
    planned_decision = {
        "action": "use_tool",
        "tool": "investigate_ioc",
        "params": {"ioc": "8.8.8.8"},
        "reasoning": "Short-circuit planned pivot.",
    }

    loop._build_tools_block = MagicMock(return_value="- investigate_ioc(ioc: string)")
    loop._build_findings_block = MagicMock(return_value="(none yet)")
    loop._build_response_style_block = MagicMock(return_value="")
    loop._build_chat_decision_block = MagicMock(return_value="")
    loop._build_reasoning_block = MagicMock(return_value="Reasoning status: collecting_evidence")
    loop._build_profile_block = MagicMock(return_value="")
    loop._build_workflow_block = MagicMock(return_value="")
    loop._build_playbooks_block = MagicMock(return_value="")
    loop._filter_tools_for_goal = MagicMock(
        return_value=[{"function": {"name": "investigate_ioc", "description": "Investigate IOC", "parameters": {}}}]
    )
    loop._chat_short_circuit_decision = MagicMock(return_value=planned_decision)
    loop.prompt_composer.build_think_payload = MagicMock()
    loop._chat_with_tools = AsyncMock()

    result = asyncio.run(loop._think(state))

    assert result == planned_decision
    loop.prompt_composer.build_think_payload.assert_not_called()
    loop._chat_with_tools.assert_not_awaited()


@pytest.mark.parametrize(
    ("method_name", "builder_method_name"),
    [
        ("_build_direct_chat_fallback_answer", "build_direct_chat_fallback_answer_with_runtime_status"),
        ("_llm_unavailable_notice", "build_runtime_unavailable_notice"),
    ],
)
def test_runtime_fallback_helpers_delegate_runtime_status_inputs(method_name, builder_method_name):
    loop = _build_agent_loop()
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return "delegated-result"

    setattr(loop.session_response_builder, builder_method_name, _capture)

    result = getattr(loop, method_name)("ignored-goal") if method_name == "_build_direct_chat_fallback_answer" else getattr(loop, method_name)()

    assert result == "delegated-result"
    assert captured["provider_runtime_status"] is loop.provider_runtime_status
    assert captured["provider_name"] == loop.provider
    assert captured["normalize_provider"] == loop._normalize_provider
    assert captured["active_model_name"] == loop._active_model_name
    assert captured["provider_display_name"] == loop.session_response_builder.provider_display_name
    assert captured["provider_runtime_error_excerpt"] == loop.session_response_builder.provider_runtime_error_excerpt



def test_build_chat_model_unavailable_answer_delegates_runtime_status_directly():
    loop = _build_agent_loop()
    state = _build_state()
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return "delegated-result"

    loop.session_response_builder.build_chat_model_unavailable_answer_with_runtime_status = _capture
    loop._resolve_authoritative_outcome = MagicMock(return_value={"label": "CLEAN"})

    result = loop._build_chat_model_unavailable_answer(state)

    assert result == "delegated-result"
    assert captured["state"] is state
    assert captured["provider_runtime_status"] is loop.provider_runtime_status
    assert captured["provider_name"] == loop.provider
    assert captured["normalize_provider"] == loop._normalize_provider
    assert captured["active_model_name"] == loop._active_model_name
    assert captured["goal"] == state.goal
    assert captured["authoritative_outcome"] == {"label": "CLEAN"}
    assert captured["build_direct_chat_fallback_answer"] == loop._build_direct_chat_fallback_answer
    assert captured["provider_display_name"] == loop.session_response_builder.provider_display_name
    assert captured["provider_runtime_error_excerpt"] == loop.session_response_builder.provider_runtime_error_excerpt


def test_response_builder_approval_helpers_shape_loop_payloads():
    loop = _build_agent_loop()
    state = _build_state()
    state.workflow_id = "wf-1"
    state.active_specialist = "triage"
    state.step_count = 2
    state.reasoning_state = {"status": "collecting_evidence"}
    state.investigation_plan = {
        "stopping_conditions": ["Enough deterministic evidence"],
        "escalation_conditions": ["Need analyst approval"],
    }

    approval_context = loop.session_response_builder.build_approval_context(
        session_id="sess-1",
        state=state,
        tool_name="block_ip",
        params={"ip": "185.220.101.45"},
        approval_id="appr-1",
        case_id="case-1",
        execution_guidance={"lane": "log_identity"},
    )
    event = loop.session_response_builder.build_approval_required_event(
        tool_name="block_ip",
        params={"ip": "185.220.101.45"},
        reason="Tool 'block_ip' requires analyst approval before execution.",
        approval_context=approval_context,
    )
    finding = loop.session_response_builder.build_approval_rejection_finding(
        tool_name="block_ip",
        approval_outcome={"status": "timed_out", "context": approval_context},
    )

    assert approval_context["session_id"] == "sess-1"
    assert approval_context["workflow_id"] == "wf-1"
    assert event["type"] == "approval_required"
    assert event["context"]["execution_guidance"] == {"lane": "log_identity"}
    assert finding == {
        "type": "approval_rejected",
        "tool": "block_ip",
        "status": "timed_out",
        "approval_context": approval_context,
        "execution_guidance": {"lane": "log_identity"},
    }


def test_record_tool_observation_refreshes_reasoning_and_notifies_tool_result():
    loop = _build_agent_loop()
    state = _build_state()
    state.step_count = 2
    state.max_steps = 7
    state.findings = []

    def add_finding(finding):
        state.findings.append(finding)

    state.add_finding = add_finding

    loop._refresh_reasoning_outputs = MagicMock()
    loop._sync_specialist_progress = MagicMock()
    loop.store.update_session_findings = MagicMock()
    loop._notify = MagicMock()

    loop._record_tool_observation(
        session_id="sess-1",
        state=state,
        tool_name="osint-tools.whois_lookup",
        params={"target": "example.com"},
        result={"result": {"registrar": "Example Registrar"}},
        duration_ms=321,
        specialist_progress_reason="Completed specialist action via osint-tools.whois_lookup.",
    )

    assert state.current_tool is None
    assert state.step_count == 3
    assert state.findings[-1] == {
        "type": "tool_result",
        "tool": "osint-tools.whois_lookup",
        "params": {"target": "example.com"},
        "result": {"result": {"registrar": "Example Registrar"}},
    }
    loop._refresh_reasoning_outputs.assert_called_once_with(
        "sess-1",
        state,
        tool_name="osint-tools.whois_lookup",
        params={"target": "example.com"},
        result={"result": {"registrar": "Example Registrar"}},
    )
    loop._sync_specialist_progress.assert_called_once_with(
        "sess-1",
        state,
        reason="Completed specialist action via osint-tools.whois_lookup.",
    )
    loop.store.update_session_findings.assert_called_once_with("sess-1", state.findings)
    loop._notify.assert_called_once_with(
        "sess-1",
        {
            "type": "tool_result",
            "step": 2,
            "max_steps": 7,
            "tool": "osint-tools.whois_lookup",
            "tool_source": "mcp",
            "tool_server": "osint-tools",
            "duration_ms": 321,
            "params": {"target": "example.com"},
            "result": {"result": {"registrar": "Example Registrar"}},
        },
    )
