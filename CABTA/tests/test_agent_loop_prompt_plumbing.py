import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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
