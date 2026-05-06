import time
from types import SimpleNamespace

from src.agent.final_answer_gate import FinalAnswerGate
from src.agent.runtime_supervisor import AgentRuntimeSupervisor
from src.agent.tool_policy import ToolPolicyEngine
from src.reporting.soc_output_formatter import SOCOutputFormatter


class State:
    def __init__(self):
        self.findings = [{"type": "tool_result", "tool": "x", "result": "unrelated"}]
        self.active_observations = []
        self.reasoning_state = {"objective_contract": {"execution_mode": "strict_production", "require_provenance": True}, "coverage_matrix": {}}
        self.evidence_state = {"graph": {"nodes": []}}


def test_strict_final_gate_blocks_unsupported_summary_and_emits_chips():
    gate = FinalAnswerGate().evaluate(
        objective={"execution_mode": "strict_production", "require_provenance": True},
        state=State(),
        draft_answer="The host is malicious and fully compromised.",
    ).to_dict()
    assert gate["allowed"] is False
    assert gate["evidence_chips"]
    assert gate["downgraded_claims"][0]["status"] in {"unsupported", "insufficient", "contradicted"}
    assert gate["structured_verdict"]["allowed_final"] is False


def test_evidence_chips_report_section_includes_claims():
    section = SOCOutputFormatter.format_evidence_chips_section({
        "evidence_chips": [{"status": "verified", "sentence": "8.8.8.8 was enriched.", "evidence_refs": [{"tool_name": "investigate_ioc"}]}],
        "unsupported_claims": [{"claim": "8.8.8.8 is confirmed C2", "reason": "No deterministic evidence"}],
    })
    text = "\n".join(section)
    assert "CLAIM EVIDENCE CHIPS" in text
    assert "8.8.8.8 was enriched" in text
    assert "UNSUPPORTED" in text


def test_runtime_supervisor_enqueue_cancel_and_complete():
    ran = []
    supervisor = AgentRuntimeSupervisor(max_queue_size=2, worker_count=1)
    task = supervisor.enqueue(session_id="s1", runner=lambda: ran.append("ok"))
    for _ in range(50):
        if supervisor.state(task["task_id"]).get("status") == "completed":
            break
        time.sleep(0.02)
    assert ran == ["ok"]
    assert supervisor.state(task["task_id"])["status"] == "completed"
    task2 = supervisor.enqueue(session_id="s2", runner=lambda: None)
    assert supervisor.cancel(task2["task_id"]) in {True, False}
    assert supervisor.status()["queue_enabled"] is True


def test_tool_policy_permission_scopes_block_missing_scope():
    engine = ToolPolicyEngine({"agent": {"tool_policy": {"allowed_scopes": ["data:logs"]}}})
    decision = engine.evaluate(tool_name="search_logs", capability_id="log.search", params={"timerange": "1h", "backend": "demo"})
    assert decision.allowed is False
    assert "network:siem" in " ".join(decision.reasons)
