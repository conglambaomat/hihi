from types import SimpleNamespace

from src.agent.decision_aggregator import DecisionAggregator
from src.agent.events import AgentEvent
from src.agent.final_answer_gate import ClaimVerifier
from src.agent.governance_store import GovernanceStore


def test_decision_aggregator_conservatively_handles_conflicting_verdicts():
    findings = [
        {"type": "tool_result", "tool": "investigate_ioc", "step": 0, "result": {"verdict": "CLEAN", "confidence": 0.9}},
        {"type": "tool_result", "tool": "analyze_malware", "step": 1, "result": {"verdict": "MALICIOUS", "severity": "critical", "confidence": 0.8}},
    ]

    decision = DecisionAggregator().aggregate(findings=findings, coverage={"overall_status": "complete"}, objective={"contract_id": "obj-1"})

    assert decision["verdict"] == "SUSPICIOUS"
    assert decision["contradiction_status"] == "contradicted"
    assert decision["authoritative_for_verdict"] is False
    assert decision["source_refs"]


def test_decision_aggregator_prefers_source_authority_over_last_result():
    findings = [
        {"type": "tool_result", "tool": "analyze_malware", "step": 0, "result": {"verdict": "MALICIOUS", "confidence": 0.75}},
        {"type": "tool_result", "tool": "search_logs", "step": 1, "result": {"verdict": "MALICIOUS", "confidence": 0.99}},
    ]

    decision = DecisionAggregator().aggregate(findings=findings, coverage={}, objective={})

    assert decision["source"] == "analyze_malware"
    assert decision["authoritative_for_verdict"] is True


def test_claim_verifier_blocks_vietnamese_verdict_without_authoritative_evidence():
    state = SimpleNamespace(
        findings=[{"type": "tool_result", "tool": "investigate_ioc", "step": 0, "result": {"verdict": "UNKNOWN"}}],
        deterministic_decision={"verdict": "UNKNOWN", "authoritative_for_verdict": False, "contradiction_status": "none"},
    )

    result = ClaimVerifier().verify(draft_answer="IOC này độc hại và cần chặn ngay.", state=state, objective={})

    assert result[0].status == "downgraded"
    assert "authoritative deterministic" in result[0].limitation


def test_agent_event_redacts_secrets_and_governance_store_lists_events_and_feedback(tmp_path):
    store = GovernanceStore(db_path=str(tmp_path / "governance.db"))
    event = AgentEvent.create(session_id="s1", event_type="tool.start", payload={"api_key": "secret", "tool": "x"})
    store.record_agent_event(**event.to_dict())

    events = store.list_agent_events(session_id="s1")
    assert events[0]["payload"]["api_key"] == "[redacted]"
    assert events[0]["event_type"] == "tool.start"

    feedback_id = store.record_structured_feedback(
        session_id="s1",
        feedback_type="claim_correctness",
        target_type="claim",
        target_ref="claim-1",
        verdict="incorrect",
        useful=False,
        comment="Unsupported claim",
    )
    feedback = store.list_decision_feedback(session_id="s1")
    assert feedback[0]["id"] == feedback_id
    assert feedback[0]["target"]["target_type"] == "claim"
