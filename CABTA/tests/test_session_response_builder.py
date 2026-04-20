import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.session_response_builder import SessionResponseBuilder


def test_build_fallback_decision_without_llm_returns_direct_answer_for_chat_without_findings():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[])

    result = builder.build_fallback_decision_without_llm(
        state=state,
        chat_prefers_direct_response=True,
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="hello",
        build_next_action_from_context=lambda _state: {"action": "use_tool", "tool": "investigate_ioc", "params": {}},
        has_tool=lambda _tool: True,
        resolve_authoritative_outcome=lambda _state: None,
        is_chat_session=lambda _state: True,
        provider_is_currently_unavailable=lambda _provider: False,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "unavailable",
        build_fallback_answer=lambda _state, _outcome: "fallback",
    )

    assert result == {
        "action": "final_answer",
        "answer": "direct:hello",
        "verdict": "UNKNOWN",
        "reasoning": "Fallback: direct analyst chat response without tool use.",
    }


def test_build_fallback_decision_without_llm_returns_correlate_findings_when_evidence_exists():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        findings=[
            {"type": "tool_result", "tool": "investigate_ioc", "result": {"verdict": "SUSPICIOUS"}},
            {"type": "tool_result", "tool": "whois_lookup", "result": {"registrar": "Example"}},
        ]
    )

    result = builder.build_fallback_decision_without_llm(
        state=state,
        chat_prefers_direct_response=False,
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="Investigate 1.2.3.4",
        build_next_action_from_context=lambda _state: {"action": "use_tool", "tool": "investigate_ioc", "params": {}},
        has_tool=lambda tool: tool == "correlate_findings",
        resolve_authoritative_outcome=lambda _state: {"label": "SUSPICIOUS"},
        is_chat_session=lambda _state: False,
        provider_is_currently_unavailable=lambda _provider: False,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "unavailable",
        build_fallback_answer=lambda _state, _outcome: "fallback",
    )

    assert result["action"] == "use_tool"
    assert result["tool"] == "correlate_findings"
    assert result["params"]["findings"] == state.findings[-10:]
    assert "correlate the accumulated evidence" in result["reasoning"]


def test_build_fallback_decision_without_llm_returns_unavailable_chat_answer_when_provider_is_down():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        findings=[
            {"type": "tool_result", "tool": "correlate_findings", "result": {"verdict": "MALICIOUS"}}
        ]
    )

    result = builder.build_fallback_decision_without_llm(
        state=state,
        chat_prefers_direct_response=False,
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="Summarize the evidence",
        build_next_action_from_context=lambda _state: {"action": "use_tool", "tool": "investigate_ioc", "params": {}},
        has_tool=lambda _tool: True,
        resolve_authoritative_outcome=lambda _state: {"label": "MALICIOUS"},
        is_chat_session=lambda _state: True,
        provider_is_currently_unavailable=lambda _provider: True,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "provider unavailable preserved state",
        build_fallback_answer=lambda _state, _outcome: "fallback",
    )

    assert result == {
        "action": "final_answer",
        "answer": "provider unavailable preserved state",
        "verdict": "MALICIOUS",
        "reasoning": (
            "Fallback: the configured chat model is unavailable, so preserve the investigation state "
            "without generating a deterministic narrative answer."
        ),
    }


@pytest.mark.asyncio
async def test_generate_summary_prefers_llm_text_when_available():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "investigate_ioc"}], errors=[])

    async def call_llm_text(prompt):
        assert "Summarise" in prompt
        return "LLM summary"

    result = await builder.generate_summary(
        state=state,
        authoritative_outcome=None,
        prompt="Summarise the investigation",
        call_llm_text=call_llm_text,
        is_chat_session=lambda _state: False,
        provider_is_currently_unavailable=lambda _provider: False,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "unavailable",
        build_fallback_answer=lambda _state, _outcome: "fallback",
    )

    assert result == "LLM summary"


@pytest.mark.asyncio
async def test_generate_summary_returns_unavailable_chat_answer_when_provider_is_down():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings"}], errors=[])

    async def call_llm_text(_prompt):
        return None

    result = await builder.generate_summary(
        state=state,
        authoritative_outcome={"label": "SUSPICIOUS"},
        prompt="Summarise the investigation",
        call_llm_text=call_llm_text,
        is_chat_session=lambda _state: True,
        provider_is_currently_unavailable=lambda _provider: True,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "provider unavailable preserved state",
        build_fallback_answer=lambda _state, _outcome: "fallback",
    )

    assert result == "provider unavailable preserved state"


def test_build_planned_next_step_summary_includes_compact_metadata():
    builder = SessionResponseBuilder()

    result = builder.build_planned_next_step_summary(
        decision={
            "tool": "search_logs",
            "decision_source": "telemetry_gap_log_pivot",
            "plan_lane": "log_identity",
            "focus": "185.220.101.45",
            "question_bundle": [
                "Which user is associated with the suspicious IP activity?",
                "Need host and user telemetry.",
            ],
        }
    )

    assert "Next planned step: search_logs." in result
    assert "Source: telemetry_gap_log_pivot." in result
    assert "Lane: log_identity." in result
    assert "Focus: 185.220.101.45." in result
    assert "Open question: Which user is associated with the suspicious IP activity?" in result


def test_build_planned_next_step_summary_returns_empty_for_non_tool_decision():
    builder = SessionResponseBuilder()

    result = builder.build_planned_next_step_summary(
        decision={"action": "final_answer", "answer": "done"}
    )

    assert result == ""
