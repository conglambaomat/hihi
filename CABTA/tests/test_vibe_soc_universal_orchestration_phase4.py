from __future__ import annotations

from types import SimpleNamespace

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState
from src.agent.final_answer_gate import FinalAnswerGate
from src.agent.reflection_engine import ReflectionEngine


def _log_objective(timerange: str = "all_time") -> dict:
    return {
        "objective_type": "investigation",
        "lane": "log_security",
        "summary": "Hunt Fortigate/Splunk logs for suspicious activity",
        "effective_timerange": timerange,
        "capabilities_required": ["log.search"],
        "evidence_requirements": [
            {
                "requirement_id": "req-log",
                "capability": "log.search",
                "required_facets": ["timestamp", "source", "destination", "action", "backend"],
                "blocking": True,
            }
        ],
    }


def test_final_answer_gate_blocks_log_investigation_when_log_evidence_missing() -> None:
    state = AgentState(session_id="phase4-missing", goal="Investigate Splunk logs")
    state.reasoning_state = {
        "objective_contract": _log_objective(),
        "coverage_matrix": {
            "missing_facets": ["timestamp", "source", "destination", "action"],
            "overall_status": "missing",
        },
    }

    decision = FinalAnswerGate().evaluate(
        objective=state.reasoning_state["objective_contract"],
        state=state,
        draft_answer="The activity is clean.",
    )

    assert decision.allowed is False
    assert decision.mode == "provisional_evidence_gap"
    assert any("log.search" in reason for reason in decision.blocking_reasons)
    assert any(claim.status == "downgraded" for claim in decision.downgraded_claims)
    assert "not a malicious/clean conclusion" in decision.provisional_answer


def test_final_answer_gate_allows_direct_capability_explanation_without_tool_evidence() -> None:
    state = AgentState(session_id="phase4-direct", goal="What log capabilities are configured?")
    objective = {
        "objective_type": "capability_explanation",
        "lane": "integration_control",
        "summary": "Explain configured capabilities",
        "capabilities_required": ["config.capability.explain"],
    }

    decision = FinalAnswerGate().evaluate(
        objective=objective,
        state=state,
        draft_answer="AISA can explain configured log and IOC capabilities.",
    )

    assert decision.allowed is True
    assert decision.mode == "direct_or_explanation_allowed"
    assert decision.blocking_reasons == []


def test_reflection_engine_detects_wrong_timerange_and_empty_log_results() -> None:
    objective = _log_objective(timerange="all_time")
    findings = [
        {
            "type": "tool_result",
            "tool": "search_logs",
            "capability": "log.search",
            "params": {"timerange": "24h"},
            "result": {
                "effective_timerange": "24h",
                "results_count": 0,
                "coverage_matrix": {"missing_facets": ["source", "destination", "action"]},
            },
        }
    ]

    reflection = ReflectionEngine().reflect(
        objective=objective,
        findings=findings,
        observations=[],
        coverage={"missing_facets": ["source", "destination", "action"]},
        reasoning_state={},
    )

    assert reflection.status == "blocked"
    assert any("timerange mismatch" in reason for reason in reflection.blocking_reasons)
    assert any(item.capability == "log.search" for item in reflection.repair_recommendations)


def test_agent_loop_final_answer_gate_produces_provisional_gap_response() -> None:
    loop = AgentLoop.__new__(AgentLoop)
    loop.reflection_engine = ReflectionEngine()
    loop.final_answer_gate = FinalAnswerGate(reflection_engine=loop.reflection_engine)

    state = AgentState(session_id="phase4-loop", goal="Investigate Splunk logs")
    state.reasoning_state = {
        "objective_contract": _log_objective(),
        "coverage_matrix": {"missing_facets": ["timestamp", "source"], "overall_status": "missing"},
    }
    state.deterministic_decision = {"verdict": "UNKNOWN"}

    gate_decision = loop._evaluate_final_answer_gate(state, "This is clean.")

    assert gate_decision.allowed is False
    assert gate_decision.mode == "provisional_evidence_gap"
    assert "cannot support a final verdict" in gate_decision.provisional_answer
    assert state.reasoning_state["final_answer_gate"]["allowed"] is False
