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


def test_generate_summary_prefers_llm_text_when_available():
    import asyncio

    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "investigate_ioc"}], errors=[])

    async def call_llm_text(prompt):
        assert "Summarise" in prompt
        return "LLM summary"

    result = asyncio.run(
        builder.generate_summary(
            state=state,
            authoritative_outcome=None,
            prompt="Summarise the investigation",
            call_llm_text=call_llm_text,
            is_chat_session=lambda _state: False,
            provider_is_currently_unavailable=lambda _provider: False,
            provider_name="openrouter",
            build_chat_model_unavailable_answer=lambda _state: "unavailable",
            build_fallback_answer=lambda _state, _outcome, _include_runtime_notice: "fallback",
        )
    )

    assert result == "LLM summary"


def test_generate_summary_returns_unavailable_chat_answer_when_provider_is_down():
    import asyncio

    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings"}], errors=[])

    async def call_llm_text(_prompt):
        return None

    result = asyncio.run(
        builder.generate_summary(
            state=state,
            authoritative_outcome={"label": "SUSPICIOUS"},
            prompt="Summarise the investigation",
            call_llm_text=call_llm_text,
            is_chat_session=lambda _state: True,
            provider_is_currently_unavailable=lambda _provider: True,
            provider_name="openrouter",
            build_chat_model_unavailable_answer=lambda _state: "provider unavailable preserved state",
            build_fallback_answer=lambda _state, _outcome, _include_runtime_notice: "fallback",
        )
    )

    assert result == "provider unavailable preserved state"


def test_summary_from_final_answer_prefixes_authoritative_outcome_when_answer_is_normal():
    builder = SessionResponseBuilder()

    result = builder.summary_from_final_answer(
        findings=[{"type": "final_answer", "answer": "Investigation complete."}],
        authoritative_outcome={"label": "MALICIOUS"},
    )

    assert result == "[MALICIOUS] Investigation complete."


def test_summary_from_final_answer_keeps_runtime_unavailable_answer_unprefixed():
    builder = SessionResponseBuilder()

    result = builder.summary_from_final_answer(
        findings=[
            {
                "type": "final_answer",
                "answer": "Provider model is currently unavailable. CABTA did not fall back to another model.",
            }
        ],
        authoritative_outcome={"label": "CLEAN"},
    )

    assert result == "Provider model is currently unavailable. CABTA did not fall back to another model."


def test_build_chat_specific_fallback_returns_mapping_for_chat_lookup_questions():
    builder = SessionResponseBuilder()

    result = builder.build_chat_specific_fallback(
        is_chat_session=True,
        focused_goal="What organization and hostname are tied to this IP?",
        findings=[
            {
                "type": "tool_result",
                "result": {
                    "organization": "Example Telecom",
                    "hostnames": ["edge.example.net"],
                },
            }
        ],
        reasoning_state={"goal_focus": "8.8.8.8"},
    )

    assert result == (
        "For 8.8.8.8, the strongest current mapping is organization Example Telecom "
        "and hostname edge.example.net."
    )



def test_build_provider_runtime_fallback_context_normalizes_provider_and_model():
    builder = SessionResponseBuilder()

    result = builder.build_provider_runtime_fallback_context(
        provider_runtime_status={"provider": "gemini", "available": False, "error": "quota exceeded"},
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"model-for:{provider}",
    )

    assert result == {
        "provider_name": "openrouter",
        "status": {"provider": "gemini", "available": False, "error": "quota exceeded"},
        "active_model_name": "model-for:openrouter",
    }


def test_build_fallback_response_context_delegates_to_provider_runtime_context_builder():
    builder = SessionResponseBuilder()

    result = builder.build_fallback_response_context(
        provider_runtime_status={"provider": "gemini", "available": False, "error": "quota exceeded"},
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"model-for:{provider}",
    )

    assert result == {
        "provider_name": "openrouter",
        "status": {"provider": "gemini", "available": False, "error": "quota exceeded"},
        "active_model_name": "model-for:openrouter",
    }


def test_build_runtime_fallback_artifacts_returns_shared_context_and_notice():
    builder = SessionResponseBuilder()

    result = builder.build_runtime_fallback_artifacts(
        provider_runtime_status={
            "provider": "gemini",
            "available": False,
            "error": "Gemini HTTP 429: quota exceeded",
        },
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"{provider}/model-a",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert result["fallback_context"] == {
        "provider_name": "openrouter",
        "status": {
            "provider": "gemini",
            "available": False,
            "error": "Gemini HTTP 429: quota exceeded",
        },
        "active_model_name": "openrouter/model-a",
    }
    assert result["llm_unavailable_notice"].startswith(
        "Gemini model openrouter/model-a is currently unavailable"
    )
    assert "did not fall back to another model" in result["llm_unavailable_notice"]



def test_llm_unavailable_notice_from_context_reuses_contextual_provider_metadata():
    builder = SessionResponseBuilder()

    result = builder.llm_unavailable_notice_from_context(
        fallback_context={
            "provider_name": "openrouter",
            "active_model_name": "openrouter/model-a",
            "status": {"provider": "gemini", "available": False, "error": "Gemini HTTP 429: quota exceeded"},
        },
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert "Gemini model openrouter/model-a is currently unavailable" in result
    assert "rate limit" in result.lower()
    assert "did not fall back to another model" in result


def test_build_provider_timeout_error_uses_provider_display_name():
    builder = SessionResponseBuilder()

    result = builder.build_provider_timeout_error(
        provider="nvidia",
        timeout_seconds=8,
        provider_display_name=builder.provider_display_name,
    )

    assert result == "NVIDIA Build direct chat request timed out after 8s"


def test_build_chat_model_unavailable_answer_from_context_reuses_fallback_context_and_deterministic_summary():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings", "result": {"verdict": "CLEAN"}}])

    result = builder.build_chat_model_unavailable_answer_from_context(
        state=state,
        fallback_context={
            "provider_name": "openrouter",
            "active_model_name": "openrouter/model-a",
            "status": {"provider": "gemini", "available": False, "error": "Gemini HTTP 429: quota exceeded"},
        },
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="Summarize the evidence",
        authoritative_outcome={"label": "CLEAN"},
        fallback_evidence_points=lambda _state, limit: ["Evidence point"][:limit],
        build_chat_specific_fallback=lambda _state: "chat-specific",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert result.startswith("Gemini model openrouter/model-a is currently unavailable")
    assert "The investigation completed 0 steps before switching to a deterministic fallback summary." not in result
    assert "Evidence-backed outcome: CLEAN." in result
    assert "Key evidence: Evidence point" in result
    assert "did not fall back to another model" in result


def test_build_unavailable_model_preserved_outputs_answer_reuses_notice_wording():
    builder = SessionResponseBuilder()

    result = builder.build_unavailable_model_preserved_outputs_answer(
        llm_unavailable_notice="Gemini model openrouter/model-a is currently unavailable. CABTA did not fall back to another model.",
    )

    assert result.startswith("Gemini model openrouter/model-a is currently unavailable")
    assert "preserved the collected tool outputs" in result


def test_build_fallback_answer_can_skip_runtime_notice_when_requested():
    builder = SessionResponseBuilder()
    calls = []

    result = builder.build_fallback_answer(
        state=SimpleNamespace(),
        authoritative_outcome={"label": "CLEAN"},
        include_runtime_notice=False,
        build_evidence_backed_answer=lambda **kwargs: calls.append(kwargs["include_runtime_notice"]) or "fallback",
    )

    assert result == "fallback"
    assert calls == [False]



def test_build_runtime_unavailable_notice_builds_context_internally():
    builder = SessionResponseBuilder()

    result = builder.build_runtime_unavailable_notice(
        provider_runtime_status={
            "provider": "gemini",
            "available": False,
            "error": "Gemini HTTP 429: quota exceeded",
        },
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"{provider}/model-a",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert "Gemini model openrouter/model-a is currently unavailable" in result
    assert "did not fall back to another model" in result


def test_llm_unavailable_notice_with_runtime_status_delegates_to_runtime_notice_builder():
    builder = SessionResponseBuilder()

    result = builder.llm_unavailable_notice_with_runtime_status(
        provider_runtime_status={
            "provider": "gemini",
            "available": False,
            "error": "Gemini HTTP 429: quota exceeded",
        },
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"{provider}/model-a",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert "Gemini model openrouter/model-a is currently unavailable" in result
    assert "did not fall back to another model" in result



def test_build_direct_chat_fallback_answer_with_runtime_status_reuses_runtime_notice_builder():
    builder = SessionResponseBuilder()

    result = builder.build_direct_chat_fallback_answer_with_runtime_status(
        provider_runtime_status={
            "provider": "gemini",
            "available": False,
            "error": "Gemini HTTP 429: quota exceeded",
        },
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"{provider}/model-a",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert result.startswith("Gemini model openrouter/model-a is currently unavailable")
    assert "Please share a concrete IOC" in result



def test_build_chat_model_unavailable_answer_with_runtime_status_reuses_runtime_context_builder():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings", "result": {"verdict": "CLEAN"}}])

    result = builder.build_chat_model_unavailable_answer_with_runtime_status(
        state=state,
        provider_runtime_status={
            "provider": "gemini",
            "available": False,
            "error": "Gemini HTTP 429: quota exceeded",
        },
        provider_name="OpenRouter",
        normalize_provider=lambda provider: str(provider).lower(),
        active_model_name=lambda provider: f"{provider}/model-a",
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="Summarize the evidence",
        authoritative_outcome={"label": "CLEAN"},
        fallback_evidence_points=lambda _state, limit: ["Evidence point"][:limit],
        build_chat_specific_fallback=lambda _state: "chat-specific",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert result.startswith("Gemini model openrouter/model-a is currently unavailable")
    assert "Evidence-backed outcome: CLEAN." in result
    assert "Key evidence: Evidence point" in result



def test_build_chat_model_unavailable_answer_from_runtime_artifacts_reuses_precomputed_notice():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings", "result": {"verdict": "CLEAN"}}])
    calls = []

    def _raising_excerpt(**_kwargs):
        calls.append("recomputed")
        raise AssertionError("should not recompute runtime excerpt")

    result = builder.build_chat_model_unavailable_answer_from_runtime_artifacts(
        state=state,
        runtime_artifacts={
            "fallback_context": {
                "provider_name": "openrouter",
                "active_model_name": "openrouter/model-a",
                "status": {"provider": "gemini", "available": False, "error": "Gemini HTTP 429: quota exceeded"},
            },
            "llm_unavailable_notice": "Precomputed unavailable notice.",
        },
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="Summarize the evidence",
        authoritative_outcome={"label": "CLEAN"},
        fallback_evidence_points=lambda _state, limit: ["Evidence point"][:limit],
        build_chat_specific_fallback=lambda _state: "chat-specific",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=_raising_excerpt,
    )

    assert result.startswith("Precomputed unavailable notice.")
    assert "Evidence-backed outcome: CLEAN." in result
    assert calls == []


def test_build_chat_model_unavailable_answer_from_context_uses_supplied_notice_without_recomputing():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings", "result": {"verdict": "CLEAN"}}])
    calls = []

    def _raising_excerpt(**_kwargs):
        calls.append("recomputed")
        raise AssertionError("should not recompute runtime excerpt")

    result = builder.build_chat_model_unavailable_answer_from_context(
        state=state,
        fallback_context={
            "provider_name": "openrouter",
            "active_model_name": "openrouter/model-a",
            "status": {"provider": "gemini", "available": False, "error": "Gemini HTTP 429: quota exceeded"},
        },
        build_direct_chat_fallback_answer=lambda goal: f"direct:{goal}",
        goal="Summarize the evidence",
        authoritative_outcome={"label": "CLEAN"},
        fallback_evidence_points=lambda _state, limit: ["Evidence point"][:limit],
        build_chat_specific_fallback=lambda _state: "chat-specific",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=_raising_excerpt,
        llm_unavailable_notice="Precomputed unavailable notice.",
    )

    assert result.startswith("Precomputed unavailable notice.")
    assert "Evidence-backed outcome: CLEAN." in result
    assert calls == []



def test_build_provider_timeout_runtime_status_builds_unavailable_status_payload():
    builder = SessionResponseBuilder()

    result = builder.build_provider_timeout_runtime_status(
        provider="NVIDIA",
        timeout_seconds=8,
        provider_display_name=builder.provider_display_name,
    )

    assert result == {
        "provider": "nvidia",
        "available": False,
        "error": "NVIDIA Build direct chat request timed out after 8s",
    }


def test_build_summary_fallback_answer_prefers_chat_unavailable_path_when_provider_is_down():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings"}])

    result = builder.build_summary_fallback_answer(
        state=state,
        authoritative_outcome={"label": "SUSPICIOUS"},
        is_chat_session=lambda _state: True,
        provider_is_currently_unavailable=lambda _provider: True,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "provider unavailable preserved state",
        build_fallback_answer=lambda _state, _outcome, _include_runtime_notice: "fallback",
    )

    assert result == "provider unavailable preserved state"


def test_build_summary_fallback_answer_uses_runtime_notice_for_deterministic_summary():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings"}])
    calls = []

    result = builder.build_summary_fallback_answer(
        state=state,
        authoritative_outcome={"label": "CLEAN"},
        is_chat_session=lambda _state: False,
        provider_is_currently_unavailable=lambda _provider: False,
        provider_name="openrouter",
        build_chat_model_unavailable_answer=lambda _state: "provider unavailable preserved state",
        build_fallback_answer=lambda _state, _outcome, include_runtime_notice: calls.append(include_runtime_notice) or "fallback",
    )

    assert result == "fallback"
    assert calls == [True]


@pytest.mark.asyncio
async def test_generate_summary_with_runtime_fallback_returns_summary_fallback_on_builder_error():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(findings=[{"type": "tool_result", "tool": "correlate_findings"}], errors=[])

    async def call_llm_text(_prompt):
        return "unused"

    async def raise_from_generate_summary(**_kwargs):
        raise RuntimeError("summary failure")

    original = builder.generate_summary
    builder.generate_summary = raise_from_generate_summary
    try:
        result = await builder.generate_summary_with_runtime_fallback(
            state=state,
            authoritative_outcome={"label": "SUSPICIOUS"},
            prompt="Summarise the investigation",
            call_llm_text=call_llm_text,
            is_chat_session=lambda _state: False,
            provider_is_currently_unavailable=lambda _provider: False,
            provider_name="openrouter",
            build_chat_model_unavailable_answer=lambda _state: "provider unavailable preserved state",
            build_fallback_answer=lambda _state, _outcome, include_runtime_notice: "fallback" if include_runtime_notice else "wrong",
        )
    finally:
        builder.generate_summary = original

    assert result == "fallback"



def test_build_fallback_evidence_points_deduplicates_and_limits_tool_summaries():
    builder = SessionResponseBuilder()

    result = builder.build_fallback_evidence_points(
        findings=[
            {"type": "note", "tool": "ignored", "result": {}},
            {
                "type": "tool_result",
                "tool": "investigate_ioc",
                "result": {"ioc": "8.8.8.8", "verdict": "clean", "threat_score": 10},
            },
            {
                "type": "tool_result",
                "tool": "investigate_ioc",
                "result": {"ioc": "8.8.8.8", "verdict": "clean", "threat_score": 10},
            },
            {
                "type": "tool_result",
                "tool": "osint-tools.whois_lookup",
                "result": {"target": "example.com", "creation_date": "2026-01-01"},
            },
            {
                "type": "tool_result",
                "tool": "correlate_findings",
                "result": {"severity": "high", "statistics": {"unique_iocs": 2}},
            },
        ],
        describe_fallback_evidence=lambda tool, result: builder.describe_fallback_evidence(
            tool_name=tool,
            result=result,
        ),
        limit=2,
    )

    assert result == [
        "8.8.8.8 classified as CLEAN with threat_score=10.",
        "WHOIS for example.com: created=2026-01-01.",
    ]



def test_describe_fallback_evidence_handles_supported_tool_shapes():
    builder = SessionResponseBuilder()

    assert builder.describe_fallback_evidence(
        tool_name="osint-tools.dns_resolve",
        result={"domain": "example.com", "records": {"A": ["1.1.1.1", "2.2.2.2"]}},
    ) == "DNS for example.com resolved to 1.1.1.1, 2.2.2.2."
    assert builder.describe_fallback_evidence(
        tool_name="osint-tools.ssl_certificate_info",
        result={"host": "example.com", "issuer": {"commonName": "Example CA"}, "not_after": "2027-01-01"},
    ) == "TLS certificate for example.com: issuer=Example CA, expires=2027-01-01."
    assert builder.describe_fallback_evidence(
        tool_name="correlate_findings",
        result={"severity": "medium", "statistics": {"unique_iocs": 4}},
    ) == "Correlation rated the case severity=MEDIUM across 4 unique IOCs."
    assert builder.describe_fallback_evidence(
        tool_name="custom_tool",
        result={"verdict": "suspicious"},
    ) == "custom_tool reported verdict=SUSPICIOUS."


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


def test_chat_evidence_allows_answer_without_tools_for_supported_root_cause_with_refs():
    builder = SessionResponseBuilder()

    result = builder.chat_evidence_allows_answer_without_tools(
        reasoning_status="collecting_evidence",
        root_cause={
            "status": "supported",
            "supporting_evidence_refs": ["obs-1"],
        },
        has_strong_evidence=False,
    )

    assert result is True



def test_chat_evidence_allows_answer_without_tools_requires_refs_only_when_requested():
    builder = SessionResponseBuilder()

    assert builder.chat_evidence_allows_answer_without_tools(
        reasoning_status="collecting_evidence",
        root_cause={"status": "supported"},
        has_strong_evidence=False,
    ) is False
    assert builder.chat_evidence_allows_answer_without_tools(
        reasoning_status="collecting_evidence",
        root_cause={"status": "supported"},
        has_strong_evidence=False,
        require_supported_root_cause_refs=False,
    ) is True



def test_build_planned_next_step_summary_returns_empty_for_non_tool_decision():
    builder = SessionResponseBuilder()

    result = builder.build_planned_next_step_summary(
        decision={"action": "final_answer", "answer": "done"}
    )

    assert result == ""


def test_build_think_request_metadata_uses_prompt_payload_and_planned_step_summary():
    builder = SessionResponseBuilder()

    result = builder.build_think_request_metadata(
        prompt_payload={
            "prompt_mode": "native_tooling",
            "provider_context_block": "Active specialist: triage",
            "prompt_envelope": {"user_intent": {"mode": "native_tooling"}},
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
        "prompt_envelope": {"user_intent": {"mode": "native_tooling"}},
        "model_only_chat": False,
        "uses_native_tools": True,
        "planned_next_step_summary": "Next planned step: search_logs. Source: telemetry_gap_log_pivot.",
    }


def test_mark_approval_timeout_updates_pending_approval_and_errors():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        errors=[],
        pending_approval={"tool": "block_ip", "status": "pending"},
    )

    builder.mark_approval_timeout(state=state, reviewed_at="2026-04-21T08:00:00+00:00")

    assert state.errors == ["Approval timed out (30 min)"]
    assert state.pending_approval == {
        "tool": "block_ip",
        "status": "timed_out",
        "approved": False,
        "reviewed_at": "2026-04-21T08:00:00+00:00",
    }


def test_consume_approval_outcome_clears_pending_and_persists_last_outcome():
    builder = SessionResponseBuilder()

    class _State:
        def __init__(self):
            self.pending_approval = {"tool": "block_ip", "approved": False, "status": "rejected"}
            self.last_approval_outcome = None

        def clear_approval(self):
            approval = self.pending_approval
            self.pending_approval = None
            return approval

    state = _State()

    result = builder.consume_approval_outcome(state=state)

    assert result == {"tool": "block_ip", "approved": False, "status": "rejected"}
    assert state.pending_approval is None
    assert state.last_approval_outcome == result


def test_build_terminal_status_payload_tracks_thread_recording_need():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        phase="completed",
        step_count=4,
        findings=[{"type": "tool_result"}],
    )

    result = builder.build_terminal_status_payload(state=state, summary="Done")

    assert result == {
        "status": "completed",
        "summary": "Done",
        "steps": 4,
        "record_thread_message": True,
    }


def test_build_terminal_status_payload_skips_thread_record_when_final_answer_exists():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        phase="failed",
        step_count=2,
        findings=[{"type": "final_answer", "answer": "Existing"}],
    )

    result = builder.build_terminal_status_payload(state=state, summary="Ignored")

    assert result == {
        "status": "failed",
        "summary": "Ignored",
        "steps": 2,
        "record_thread_message": False,
    }


def test_build_approval_context_keeps_orchestration_metadata_together():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        workflow_id="wf-1",
        active_specialist="triage",
        step_count=3,
        reasoning_state={"status": "collecting_evidence"},
        investigation_plan={
            "stopping_conditions": ["Enough deterministic evidence"],
            "escalation_conditions": ["Need analyst approval"],
        },
    )

    result = builder.build_approval_context(
        session_id="sess-1",
        state=state,
        tool_name="block_ip",
        params={"ip": "185.220.101.45"},
        approval_id="appr-1",
        case_id="case-1",
        execution_guidance={"lane": "log_identity"},
    )

    assert result == {
        "tool": "block_ip",
        "params": {"ip": "185.220.101.45"},
        "approval_id": "appr-1",
        "case_id": "case-1",
        "workflow_id": "wf-1",
        "specialist": "triage",
        "session_id": "sess-1",
        "step": 3,
        "reasoning_status": "collecting_evidence",
        "stop_conditions": ["Enough deterministic evidence"],
        "escalation_conditions": ["Need analyst approval"],
        "execution_guidance": {"lane": "log_identity"},
    }



def test_build_approval_required_event_reuses_context_without_mutation():
    builder = SessionResponseBuilder()
    approval_context = {
        "tool": "block_ip",
        "execution_guidance": {"lane": "log_identity"},
    }

    result = builder.build_approval_required_event(
        tool_name="block_ip",
        params={"ip": "185.220.101.45"},
        reason="Tool 'block_ip' requires analyst approval before execution.",
        approval_context=approval_context,
    )

    assert result == {
        "type": "approval_required",
        "tool": "block_ip",
        "params": {"ip": "185.220.101.45"},
        "reason": "Tool 'block_ip' requires analyst approval before execution.",
        "context": approval_context,
    }



def test_apply_approval_review_updates_pending_state():
    builder = SessionResponseBuilder()
    state = SimpleNamespace(
        pending_approval={"tool": "block_ip", "status": "pending"}
    )

    updated = builder.apply_approval_review(
        state=state,
        approved=True,
        reviewed_at="2026-04-21T08:00:00+00:00",
    )

    assert updated is True
    assert state.pending_approval == {
        "tool": "block_ip",
        "status": "approved",
        "approved": True,
        "reviewed_at": "2026-04-21T08:00:00+00:00",
    }



def test_build_approval_pending_payload_adds_approval_id_without_mutating_decision():
    builder = SessionResponseBuilder()
    decision = {"action": "use_tool", "tool": "block_ip", "params": {"ip": "185.220.101.45"}}

    result = builder.build_approval_pending_payload(
        decision=decision,
        approval_id="appr-1",
    )

    assert result == {
        "action": "use_tool",
        "tool": "block_ip",
        "params": {"ip": "185.220.101.45"},
        "approval_id": "appr-1",
    }
    assert decision == {"action": "use_tool", "tool": "block_ip", "params": {"ip": "185.220.101.45"}}



def test_build_approval_rejection_transition_preserves_timeout_context():
    builder = SessionResponseBuilder()

    result = builder.build_approval_rejection_transition(
        tool_name="block_ip",
        approval_outcome={
            "status": "timed_out",
            "context": {"execution_guidance": {"lane": "log_identity"}},
        },
    )

    assert result == {
        "finding": {
            "type": "approval_rejected",
            "tool": "block_ip",
            "status": "timed_out",
            "approval_context": {"execution_guidance": {"lane": "log_identity"}},
            "execution_guidance": {"lane": "log_identity"},
        },
        "blocker_status": "timed_out",
        "approval_context": {"execution_guidance": {"lane": "log_identity"}},
    }


def test_chat_follow_up_can_answer_from_context_requires_restored_context_and_no_fresh_evidence():
    builder = SessionResponseBuilder()

    assert builder.chat_follow_up_can_answer_from_context(
        is_chat_session=True,
        metadata={"chat_context_restored": True},
        requires_fresh_evidence=False,
        has_context_state=True,
        latest_message="Why did you mark this as suspicious?",
        goal_has_observable=lambda _message: False,
    ) is True

    assert builder.chat_follow_up_can_answer_from_context(
        is_chat_session=True,
        metadata={"chat_context_restored": True},
        requires_fresh_evidence=True,
        has_context_state=True,
        latest_message="Why did you mark this as suspicious?",
        goal_has_observable=lambda _message: False,
    ) is False


def test_message_requests_fresh_evidence_distinguishes_explanation_from_new_pivot():
    builder = SessionResponseBuilder()

    assert builder.message_requests_fresh_evidence("Pivot on registrar-linked infrastructure.") is True
    assert builder.message_requests_fresh_evidence("Giải thích vì sao bạn kết luận domain này độc hại.") is False


def test_build_legacy_follow_up_goal_mentions_when_fresh_evidence_is_required():
    builder = SessionResponseBuilder()

    result = builder.build_legacy_follow_up_goal(
        previous_goal="Investigate suspicious domain activity",
        previous_summary="Prior thread isolated suspicious registrar patterns.",
        evidence_snapshot="- investigate_ioc: verdict=SUSPICIOUS",
        message="Pivot on registrar-linked infrastructure.",
    )

    assert "Continue the previous analyst conversation" in result
    assert "Previous investigation goal:" in result
    assert "Previous investigation summary:" in result
    assert "Previous evidence snapshot:" in result
    assert "Gather fresh evidence with tools" in result


def test_build_legacy_follow_up_goal_strips_nested_follow_up_prefix_and_uses_existing_context_when_sufficient():
    builder = SessionResponseBuilder()

    result = builder.build_legacy_follow_up_goal(
        previous_goal="(Follow-up to previous investigation:\nInvestigate suspicious sign-in activity)",
        previous_summary="Prior summary",
        evidence_snapshot="- correlate_findings: verdict=SUSPICIOUS",
        message="Explain why this case stayed suspicious.",
    )

    assert "(Follow-up to previous investigation:" not in result
    assert "Previous investigation goal:\nInvestigate suspicious sign-in activity)" in result
    assert "Only use tools if the current evidence is insufficient." in result


def test_build_follow_up_goal_mentions_when_fresh_evidence_is_required():
    builder = SessionResponseBuilder()

    result = builder.build_follow_up_goal(
        previous_goal="Investigate suspicious domain activity",
        thread_summary="Prior thread isolated suspicious registrar patterns.",
        snapshot={
            "root_cause_assessment": {"summary": "Prior evidence pointed to registrar abuse."},
            "accepted_facts": [{"summary": "Registrar matched known abuse cluster."}],
            "unresolved_questions": ["Who registered the domain?"],
        },
        message="Pivot on registrar-linked infrastructure.",
        intent="new_pivot",
        requires_fresh_evidence=True,
        memory_scope="accepted",
        memory_boundary={"case_id": "CASE-1", "thread_id": "thread-1", "publication_scope": "accepted"},
        memory_kind="authoritative_case_truth",
        publication_scope="accepted",
        memory_is_authoritative=True,
    )

    assert "Continue the same analyst thread" in result
    assert "Follow-up analyst request (new_pivot):" in result
    assert "collect fresh evidence" in result
    assert "accepted case memory" in result
    assert "accepted case truth" in result
    assert "Restored memory contract: memory_scope=accepted, memory_kind=authoritative_case_truth, publication_scope=accepted, memory_is_authoritative=true" in result
    assert "memory_boundary={'case_id': 'CASE-1', 'thread_id': 'thread-1', 'publication_scope': 'accepted'}" in result
    assert "Registrar matched known abuse cluster." in result


def test_build_follow_up_goal_uses_published_memory_scope_language_when_provided():
    builder = SessionResponseBuilder()

    result = builder.build_follow_up_goal(
        previous_goal="Investigate suspicious sign-in activity",
        thread_summary="Published case memory isolated risky identity activity.",
        snapshot={
            "root_cause_assessment": {"summary": "Published case evidence supports credential misuse."},
            "accepted_facts": [{"summary": "Alice authenticated from 185.220.101.45."}],
        },
        message="Explain why this case stayed suspicious.",
        intent="follow_up_question",
        requires_fresh_evidence=False,
        memory_scope="published",
        memory_boundary={"case_id": "CASE-42", "thread_id": "case-thread-1", "session_id": "sess-case-memory", "publication_scope": "published"},
        memory_kind="authoritative_case_truth",
        publication_scope="published",
        memory_is_authoritative=True,
    )

    assert "published case memory" in result
    assert "Published case memory facts:" in result
    assert "Answer from the published case memory" in result
    assert "Restored memory contract: memory_scope=published, memory_kind=authoritative_case_truth, publication_scope=published, memory_is_authoritative=true" in result
    assert "memory_boundary={'case_id': 'CASE-42', 'thread_id': 'case-thread-1', 'session_id': 'sess-case-memory', 'publication_scope': 'published'}" in result
    assert "Do not present published case truth as more authoritative than this lifecycle allows." in result


def test_build_follow_up_goal_normalizes_working_memory_contract_when_publication_scope_is_carried():
    builder = SessionResponseBuilder()

    result = builder.build_follow_up_goal(
        previous_goal="Investigate noisy alert follow-up",
        thread_summary="Working thread context only.",
        snapshot={
            "accepted_facts": [{"summary": "Observed a low-confidence host correlation."}],
            "unresolved_questions": ["Is the host actually involved?"],
        },
        message="Explain what we know so far.",
        intent="follow_up_question",
        requires_fresh_evidence=False,
        memory_scope=None,
        memory_boundary={"case_id": "CASE-7", "publication_scope": "working"},
        memory_kind=None,
        publication_scope="working",
        memory_is_authoritative=None,
    )

    assert "working session context" in result
    assert "Do not present working session context as more authoritative than this lifecycle allows." in result
    assert "Restored memory contract: memory_scope=working, memory_kind=working_context, publication_scope=working, memory_is_authoritative=false" in result


def test_build_follow_up_goal_uses_boundary_publication_scope_when_explicit_scope_is_missing():
    builder = SessionResponseBuilder()

    result = builder.build_follow_up_goal(
        previous_goal="Investigate queued follow-up",
        thread_summary="Boundary-only lifecycle contract.",
        snapshot={"accepted_facts": [{"summary": "Queued command restored accepted case truth."}]},
        message="Explain the carried-over truth.",
        intent="follow_up_question",
        requires_fresh_evidence=False,
        memory_scope=None,
        memory_boundary={"case_id": "CASE-9", "thread_id": "thread-9", "publication_scope": "accepted"},
        memory_kind=None,
        publication_scope=None,
        memory_is_authoritative=None,
    )

    assert "accepted case memory" in result
    assert "accepted case truth" in result
    assert "Restored memory contract: memory_scope=accepted, memory_kind=authoritative_case_truth, publication_scope=accepted, memory_is_authoritative=true" in result


def test_build_chat_response_style_block_is_empty_for_non_chat_sessions():
    builder = SessionResponseBuilder()

    assert builder.build_chat_response_style_block(
        is_chat_session=False,
        chat_context_restored=True,
    ) == ""


def test_build_chat_response_style_block_mentions_restored_context_when_present():
    builder = SessionResponseBuilder()

    result = builder.build_chat_response_style_block(
        is_chat_session=True,
        chat_context_restored=True,
    )

    assert "Response style for analyst chat:" in result
    assert "Treat carried-over findings as live investigation context" in result


def test_build_chat_response_style_block_mentions_memory_scope_truth_when_restored():
    builder = SessionResponseBuilder()

    result = builder.build_chat_response_style_block(
        is_chat_session=True,
        chat_context_restored=True,
        restored_memory_scope="published",
        restored_memory_is_authoritative=True,
    )

    assert "authoritative case truth" in result
    assert "published memory" in result


def test_build_chat_prompt_policy_returns_both_blocks_for_restored_authoritative_context():
    builder = SessionResponseBuilder()

    result = builder.build_chat_prompt_policy(
        is_chat_session=True,
        chat_context_restored=True,
        requires_fresh_evidence=True,
        restored_memory_scope="published",
        restored_memory_is_authoritative=True,
    )

    assert "Response style for analyst chat:" in result["response_style_block"]
    assert "Treat carried-over findings as live investigation context" in result["response_style_block"]
    assert "published memory" in result["response_style_block"]
    assert "Chat decision policy:" in result["chat_decision_block"]
    assert "gather fresh evidence only for the new pivot" in result["chat_decision_block"]
    assert "restored published case truth" in result["chat_decision_block"]


def test_build_chat_decision_block_varies_with_follow_up_fresh_evidence_policy():
    builder = SessionResponseBuilder()

    fresh_result = builder.build_chat_decision_block(
        is_chat_session=True,
        chat_context_restored=True,
        requires_fresh_evidence=True,
        restored_memory_scope="accepted",
        restored_memory_is_authoritative=True,
    )
    restored_result = builder.build_chat_decision_block(
        is_chat_session=True,
        chat_context_restored=True,
        requires_fresh_evidence=False,
        restored_memory_scope="working",
        restored_memory_is_authoritative=False,
    )

    assert "gather fresh evidence only for the new pivot" in fresh_result
    assert "restored accepted case truth" in fresh_result
    assert "Prefer answering from the restored working context" in restored_result
