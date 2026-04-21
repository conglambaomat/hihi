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
            build_fallback_answer=lambda _state, _outcome: "fallback",
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
            build_fallback_answer=lambda _state, _outcome: "fallback",
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



def test_build_fallback_response_context_normalizes_provider_and_model():
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
        build_fallback_answer=lambda _state, _outcome: "fallback answer",
        build_chat_specific_fallback=lambda _state: "chat-specific",
        provider_display_name=builder.provider_display_name,
        provider_runtime_error_excerpt=builder.provider_runtime_error_excerpt,
    )

    assert result == "fallback answer"



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
    )

    assert "Continue the same analyst thread" in result
    assert "Follow-up analyst request (new_pivot):" in result
    assert "collect fresh evidence" in result
    assert "accepted snapshot" in result
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
    )

    assert "published case snapshot" in result
    assert "Published case snapshot facts:" in result
    assert "Answer from the published case snapshot" in result


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


def test_build_chat_decision_block_varies_with_follow_up_fresh_evidence_policy():
    builder = SessionResponseBuilder()

    fresh_result = builder.build_chat_decision_block(
        is_chat_session=True,
        chat_context_restored=True,
        requires_fresh_evidence=True,
    )
    restored_result = builder.build_chat_decision_block(
        is_chat_session=True,
        chat_context_restored=True,
        requires_fresh_evidence=False,
    )

    assert "gather fresh evidence only for the new pivot" in fresh_result
    assert "Prefer answering from that restored evidence" in restored_result
