import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.context import (
    ContextBudgetManager,
    ContextCompressor,
    ContextLedger,
    ContextOrchestrator,
    ContextRequest,
    EvidenceRetriever,
    InvestigationContextMapBuilder,
    SubInvestigationContextManager,
    estimate_text_tokens,
)


def _state():
    return SimpleNamespace(
        session_id="sess-ctx",
        step_count=3,
        goal="Investigate host WS-12 beaconing to 185.220.101.45",
        findings=[
            {"step": 1, "type": "tool_result", "tool": "search_logs", "result": {"summary": "old important c2 evidence"}, "timestamp": "2026-04-27T00:00:00Z"},
            {"step": 2, "type": "tool_result", "tool": "noop", "result": {"summary": "recent neutral"}, "timestamp": "2026-04-28T00:00:00Z"},
        ],
        reasoning_state={
            "status": "collecting_evidence",
            "goal_focus": "WS-12 185.220.101.45",
            "missing_evidence": ["Need process-to-network attribution."],
            "hypotheses": [
                {
                    "id": "hyp-c2",
                    "statement": "WS-12 is beaconing to C2 infrastructure.",
                    "confidence": 0.72,
                    "status": "supported",
                    "ranking_score": 0.8,
                    "reason_codes": ["C2_BEACON"],
                    "supporting_evidence_refs": [
                        {"tool_name": "search_logs", "step_number": 1, "finding_index": 0, "summary": "Old FortiGate log links WS-12 to 185.220.101.45", "quality": 0.9, "confidence": 0.9, "created_at": "2026-04-27T00:00:00Z"}
                    ],
                    "contradicting_evidence_refs": [
                        {"tool_name": "asset_inventory", "step_number": 0, "summary": "Host ownership is uncertain", "quality": 0.8, "confidence": 0.8}
                    ],
                }
            ],
            "coverage_matrix": {"blocking_gaps": [{"facet": "process", "status": "missing", "basis": "no_direct_evidence"}]},
        },
        entity_state={
            "entities": {
                "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12", "confidence": 0.9, "observation_count": 2, "evidence_refs": [{"tool_name": "search_logs"}]},
                "ip:185.220.101.45": {"id": "ip:185.220.101.45", "type": "ip", "value": "185.220.101.45", "confidence": 0.92, "observation_count": 2, "evidence_refs": [{"tool_name": "search_logs"}]},
            },
            "relationships": [{"source": "host:ws-12", "target": "ip:185.220.101.45", "relation": "connects_to", "relation_strength": "explicit", "confidence": 0.9}],
        },
        evidence_state={"timeline": [], "edges": []},
        deterministic_decision={"verdict": "SUSPICIOUS", "score": 65, "source": "correlate_findings"},
        agentic_explanation={"root_cause_assessment": {"status": "inconclusive", "summary": "Likely C2 but missing process attribution."}, "missing_evidence": ["Need endpoint process evidence."]},
        active_observations=[],
        accepted_facts=[],
        unresolved_questions=[],
    )


def test_context_budget_manager_estimates_tokens_and_detects_over_budget():
    assert estimate_text_tokens("abcd") >= 1
    manager = ContextBudgetManager({"agent": {"context": {"context_window_tokens": 1000, "reserved_output_tokens": 100, "safety_margin_tokens": 100, "hard_prompt_budget_tokens": 200}}})
    report = manager.budget_report(sections={"evidence": "x" * 1200}, objective="decide_next_tool", model="test")
    assert report["estimated_total"] > 0
    assert report["over_budget"] is True
    assert report["section_budgets"]["evidence"] > 0


def test_context_ledger_records_included_excluded_and_compression_actions():
    ledger = ContextLedger("led-1", "sess", 1, "decide_next_tool")
    ledger.add_included({"brief_id": "ebr-1", "kind": "evidence_brief", "authority": "tool_observation", "evidence_refs": [{"tool_name": "search_logs"}]}, reason="important")
    ledger.add_excluded({"brief_id": "ebr-2", "kind": "evidence_brief"}, reason="low relevance")
    ledger.add_compression_action("trim", item_id="ebr-2", reason="budget")
    payload = ledger.to_dict()
    assert payload["included"][0]["item_id"] == "ebr-1"
    assert payload["excluded"][0]["reason"] == "low relevance"
    assert payload["compression_actions"][0]["action"] == "trim"
    assert payload["authoritative_for_verdict"] is False


def test_context_map_and_retriever_prioritize_important_old_evidence_over_recent_neutral():
    context_map = InvestigationContextMapBuilder().build(_state(), objective="decide_next_tool")
    assert context_map["ranked_entities"][0]["id"] in {"host:ws-12", "ip:185.220.101.45"}
    selected, excluded = EvidenceRetriever().retrieve(context_map, objective="decide_next_tool", max_briefs=8)
    summaries = "\n".join(item["summary"] for item in selected)
    assert "Old FortiGate log links WS-12" in summaries
    assert any(item.get("do_not_drop") for item in selected)
    assert context_map["missing_evidence"]


def test_context_compressor_preserves_do_not_forget_and_evidence_refs():
    sections = {"authority_policy": "deterministic", "evidence_briefs": [{"brief_id": "a", "summary": "x", "evidence_ref": {"tool_name": "t"}, "do_not_drop": True, "authority": "tool_observation"}] * 3}
    compressed = ContextCompressor().compress(sections, target_tokens=10)
    assert "deterministic_decision" in compressed["do_not_forget"]
    assert compressed["evidence_briefs"][0]["source_refs"][0]["tool_name"] == "t"
    assert compressed["evidence_briefs"][0]["authority"] == "tool_observation"


def test_context_orchestrator_builds_pack_with_budget_report_and_ledger():
    orch = ContextOrchestrator({"agent": {"context": {"enabled": True}}}, model_resolver=lambda: "test-model")
    pack = orch.build_pack(state=_state(), request=ContextRequest(session_id="sess-ctx", step_number=3, model="test-model", tools_block="- search_logs", reasoning_block="legacy"))
    payload = pack.to_dict()
    assert payload["schema_version"] == "context-package/v1"
    assert payload["budget_report"]["estimated_total"] > 0
    assert payload["ledger"]["included"]
    assert payload["authority_policy"].startswith("deterministic_evidence")


def test_sub_investigation_context_contract_blocks_verdict_claims():
    packet = SubInvestigationContextManager().build_child_context(parent_session_id="sess", child_objective="verify process", allowed_tools=["search_logs"])
    assert "final verdict" in packet["blocked_claims"]
    assert packet["return_contract"]["authoritative_for_verdict"] is False


def test_sub_investigation_result_merge_preserves_non_authoritative_boundary():
    manager = SubInvestigationContextManager()
    packet = manager.build_child_context(parent_session_id="sess", child_objective="verify process", allowed_tools=["search_logs"])
    result = manager.build_child_result_contract(
        packet,
        summary="Process attribution still needs endpoint logs.",
        evidence_refs=[{"tool_name": "search_logs", "step_number": 3}],
        new_entities=[{"type": "process", "value": "unknown"}],
        coverage_delta={"still_missing_facets": ["process"]},
        hypothesis_updates=[{"hypothesis_id": "hyp-c2", "status": "open"}],
        confidence=0.4,
    )
    merged = manager.merge_child_result_into_reasoning_state({"hypotheses": []}, result)
    assert result["child_context_id"]
    assert result["authoritative_for_verdict"] is False
    assert merged["merge_metadata"]["merged_as"] == "non_authoritative_reasoning_metadata"
    assert merged["reasoning_state"]["sub_investigation_summaries"][0]["authoritative_for_verdict"] is False


def test_evidence_retriever_ranking_weights_change_order_predictably():
    context_map = {
        "ranked_evidence_refs": [
            {"tool_name": "old_tool", "summary": "old deterministic support", "authority": "tool_observation", "quality": 0.9, "score": 0.9, "recency": 0.1},
            {"tool_name": "new_tool", "summary": "fresh weak telemetry", "authority": "tool_observation", "quality": 0.2, "score": 0.2, "recency": 1.0},
        ],
        "contradictions": [],
        "missing_evidence": [],
        "coverage_gaps": [],
    }
    default_selected, _ = EvidenceRetriever().retrieve(context_map, max_briefs=2)
    recency_selected, _ = EvidenceRetriever({"context_management": {"ranking_weights": {"objective_relevance": 0.0, "evidence_quality": 0.0, "authority": 0.0, "hypothesis_or_gap": 0.0, "contradiction": 0.0, "recency": 1.0, "diversity": 0.0}}}).retrieve(context_map, max_briefs=2)
    assert default_selected[0]["evidence_ref"]["tool_name"] == "old_tool"
    assert recency_selected[0]["evidence_ref"]["tool_name"] == "new_tool"
    assert recency_selected[0]["ranking_score_detail"]["weights_version"] == "context-ranking-weights/v1"
