import json
from types import SimpleNamespace

from src.agent.coverage import CoverageEvaluator, requirements_for_lane
from src.agent.log_query_coverage import evaluate_log_result_coverage, normalize_log_coverage_matrix
from src.agent.log_query_planner import LogQueryPlanner
from src.agent.prompt_composer import PromptComposer
from src.agent.next_action_planner import NextActionPlanner
from src.agent.query_planning import InvestigationQueryPlanner, LLMQueryAssistant, QueryResultEvaluator, QueryValidator
from src.agent.retry import BacktrackingEngine, RetryPolicy, ToolResultClassifier
from src.agent.evidence_graph import EvidenceGraph
from src.utils.log_hunting_policy import evaluate_hunt_request


def test_coverage_contracts_include_expected_lanes_and_facets():
    expected = {
        "log_identity": "session",
        "email": "sender",
        "file": "file_hash",
        "network": "source_ip",
        "process": "process",
        "ioc": "ioc",
    }
    for lane, facet in expected.items():
        facets = [item.facet for item in requirements_for_lane(lane)]
        assert facet in facets


def test_coverage_evaluator_marks_direct_strong_evidence_covered_and_missing_gaps():
    matrix = CoverageEvaluator().evaluate(
        lane="log_identity",
        active_observations=[
            {
                "observation_id": "obs-1",
                "tool_name": "search_logs",
                "quality": 0.82,
                "typed_fact": {"quality": 0.82, "family": "log"},
                "canonical_facts": {"principal": "alice", "session": "S-1", "asset": "WS-12", "source_ip": "10.0.0.5"},
            }
        ],
        entity_state={"entities": {}, "relationships": []},
        evidence_state={"timeline": [{"summary": "auth event"}]},
        reasoning_state={},
    )

    assert matrix["overall_status"] == "partial"
    assert "source_ip" in matrix["covered_facets"]
    assert any(gap["facet"] == "process" for gap in matrix["blocking_gaps"])


def test_prompt_renders_compact_coverage_matrix():
    composer = PromptComposer()
    state = SimpleNamespace(
        investigation_plan={"lane": "log_identity", "lead_profile": "investigator", "primary_entities": []},
        reasoning_state={
            "status": "collecting_evidence",
            "coverage_matrix": {
                "overall_status": "partial",
                "overall_score": 0.5,
                "blocking_gaps": [{"facet": "process", "status": "missing", "basis": "no_direct_evidence"}],
            },
            "hypotheses": [{"statement": "Credential misuse", "confidence": 0.5, "status": "open"}],
        },
        active_observations=[],
        evidence_quality_summary={},
        agentic_explanation={},
        entity_state={"entities": {}},
        unresolved_questions=[],
    )

    block = composer.build_reasoning_block(state, is_chat_session=False)

    assert "Coverage matrix: status=partial, score=0.5" in block
    assert "- process (missing, basis=no_direct_evidence)" in block


def test_host_process_log_coverage_accepts_specific_runtime_facets():
    matrix = evaluate_log_result_coverage(
        query_plan={"required_facets": ["timestamp", "host", "process", "command_line", "event_code", "user", "source_sourcetype", "backend", "raw_event"], "lane": "host_process_log_hunt"},
        result={
            "results": [
                {
                    "timestamp": "2025-01-11T16:21:00Z",
                    "host": "HR-WIN-001",
                    "process_name": "powershell.exe",
                    "command_line": "Get-WmiObject -Class Win32_Bios",
                    "event_code": "1002",
                    "user": "hr-user",
                    "index": "win",
                    "sourcetype": "WinEventLog:PowerShell",
                    "backend": "demo_fixture",
                    "raw_event": "EventCode=1002 CommandLine=Get-WmiObject -Class Win32_Bios",
                }
            ],
            "executed_queries": [{"query": "host=HR-WIN-001 EventCode=1002", "matched_count": 1}],
        },
        executed=True,
    )

    assert matrix["overall_status"] == "covered"
    assert matrix["missing_facets"] == []
    assert "command_line" in matrix["covered_facets"]
    assert "source_sourcetype" in matrix["covered_facets"]


def test_fortigate_raw_log_uses_historical_bounded_specific_spl():
    raw_log = 'Aug 24 12:27:44 192.168.250.1 date=2016-08-24 time=12:27:43 devname=gotham-fortigate devid=FGT60D4614044725 logid=0000000013 type=traffic subtype=forward level=notice vd=root srcip=188.243.155.61 srcport=6631 srcintf="wan1" dstip=71.39.18.122 dstport=23 dstintf="wan1" sessionid=4237667 proto=6 action=deny policyid=0 dstcountry="United States" srccountry="Russian Federation" trandisp=noop service="TELNET" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 appcat="unscanned" crscore=30 craction=131072 crlevel=high'

    plan = LogQueryPlanner().build_plan(
        focus="/threat logs on the same firewall/device.",
        analyst_request=raw_log,
        lane="log_identity",
        unresolved_questions=["Find threat logs on the same firewall/device."],
    )

    spl = "\n".join(plan["query_bundle"]["splunk"])
    assert plan["focus"] == "188.243.155.61"
    assert plan["timerange"] != "24h"
    assert plan["timerange"] == "2016-08-24t12:17:43..2016-08-24t12:37:43"
    assert "188.243.155.61" in spl
    assert "71.39.18.122" in spl
    assert "4237667" in spl
    assert "TELNET" in spl or 'dstport="23"' in spl
    assert "index=*" not in spl
    assert "/threat logs" not in plan["focus"]
    assert all(evaluate_hunt_request(query, timerange=plan["timerange"], query_origin="generated")["status"] == "executable" for query in plan["query_bundle"]["splunk"])


def test_investigation_query_planner_validates_with_fortigate_historical_timerange():
    raw_log = 'date=2016-08-24 time=12:27:43 devname=gotham-fortigate devid=FGT60D4614044725 srcip=188.243.155.61 dstip=71.39.18.122 dstport=23 sessionid=4237667 service="TELNET" action=deny type=traffic subtype=forward'

    plan = InvestigationQueryPlanner().build_log_hunt_plan(
        goal=raw_log,
        lane="log_identity",
        focus="/search_logs threat logs on the same firewall/device.",
        unresolved_questions=["Confirm the FortiGate session."],
    )

    log_plan = plan["log_query_plan"]
    assert log_plan["focus"] == "188.243.155.61"
    assert log_plan["timerange"].startswith("2016-08-24t12:17:43")
    assert plan["validation_metadata"]["status"] == "executable"
    assert all(item["status"] == "executable" for item in plan["validation_metadata"]["validations"])


def test_investigation_query_planner_emits_validation_and_fallback_metadata():
    plan = InvestigationQueryPlanner().build_log_hunt_plan(
        goal="Investigate alice logon activity",
        lane="log_identity",
        focus="alice",
        unresolved_questions=["Which session and process are linked to alice?"],
        coverage_matrix={"missing_facets": ["session", "process"], "coverage_targets": ["session", "process"]},
    )

    assert plan["objective"]
    assert "auth_event" in plan["expected_observation_types"]
    assert plan["fallback_variants"]
    assert plan["validation_metadata"]["query_count"] >= 1
    assert plan["fingerprints"]
    assert plan["log_query_plan"]["coverage_matrix"]


def test_llm_query_assist_disabled_by_default_does_not_call_provider():
    calls = []
    planner = InvestigationQueryPlanner(llm_provider=lambda _prompt: calls.append(_prompt) or "{}")

    plan = planner.build_log_hunt_plan(
        goal="Investigate alice logon activity",
        lane="log_identity",
        focus="alice",
        coverage_matrix={"missing_facets": ["session"]},
    )

    assert calls == []
    assert plan["query_variants"]
    assert plan["llm_query_assist"]["status"] == "disabled"


def test_llm_query_assist_enabled_validates_and_appends_safe_candidate():
    response = json.dumps({
        "candidates": [
            {
                "backend": "splunk",
                "query": 'search index=main user="alice" session_id=* | head 50',
                "objective": "Find alice session identifiers.",
                "expected_facets": ["session", "user"],
                "strategy": "session_linkage",
            }
        ]
    })
    planner = InvestigationQueryPlanner(
        config={"log_hunting": {"llm_query_assist_enabled": True, "llm_query_assist_max_candidates": 3, "llm_query_assist_require_validation": True}},
        llm_provider=lambda _prompt: response,
    )

    plan = planner.build_log_hunt_plan(
        goal="Investigate alice logon activity",
        lane="log_identity",
        focus="alice",
        coverage_matrix={"missing_facets": ["session"], "coverage_targets": ["session"]},
    )

    llm_variants = [item for item in plan["query_variants"] if item.get("source") == "llm_suggestion"]
    assert llm_variants
    assert llm_variants[0]["generation_source"] == "llm_query_assist"
    assert llm_variants[0]["validation_metadata"]["status"] == "executable"
    assert plan["llm_query_assist"]["accepted_count"] == 1


def test_llm_query_assist_rejects_dangerous_candidate_before_execution():
    response = json.dumps({
        "candidates": [
            {
                "backend": "splunk",
                "query": "search index=* | outputlookup bad.csv",
                "objective": "Unsafe mutation.",
                "expected_facets": ["user"],
            }
        ]
    })
    planner = InvestigationQueryPlanner(
        config={"log_hunting": {"llm_query_assist_enabled": True}},
        llm_provider=lambda _prompt: response,
    )

    plan = planner.build_log_hunt_plan(goal="Investigate alice", lane="log_identity", focus="alice")

    assert not [item for item in plan["query_variants"] if item.get("source") == "llm_suggestion"]
    rejected = plan["llm_query_assist"]["rejected_candidates"]
    assert rejected
    assert rejected[0]["validation_metadata"]["status"] == "blocked"


def test_llm_query_assist_malformed_response_degrades_safely():
    planner = InvestigationQueryPlanner(
        config={"log_hunting": {"llm_query_assist_enabled": True}},
        llm_provider=lambda _prompt: "not json",
    )

    plan = planner.build_log_hunt_plan(goal="Investigate alice", lane="log_identity", focus="alice")

    assert plan["query_variants"]
    assert plan["llm_query_assist"]["status"] == "degraded"
    assert plan["llm_query_assist"]["accepted_count"] == 0


def test_llm_query_assist_provider_unavailable_degrades_safely():
    planner = InvestigationQueryPlanner(
        config={"log_hunting": {"llm_query_assist_enabled": True}},
        llm_provider=None,
    )

    plan = planner.build_log_hunt_plan(goal="Investigate alice", lane="log_identity", focus="alice")

    assert plan["query_variants"]
    assert plan["llm_query_assist"]["status"] == "unavailable"


def test_query_validator_blocks_dangerous_query():
    validation = QueryValidator().validate_bundle({"splunk": ["index=* | outputlookup bad.csv"]}, timerange="24h")

    assert validation["status"] == "blocked"
    assert validation["validations"][0]["status"] == "blocked"


def test_tool_result_classifier_exposes_diagnosis_taxonomy():
    classifier = ToolResultClassifier()

    diagnosis = classifier.diagnose({"status": "executed", "results_count": 0, "queries": {"splunk": ["search index=auth earliest=-1h user=alice | head 50"]}})

    assert diagnosis["diagnosis"] in classifier.DIAGNOSES
    assert diagnosis["diagnosis"] == "too_narrow_time"
    assert diagnosis["retryable"] is True


def test_tool_result_classifier_infers_schema_index_and_no_telemetry_diagnoses():
    classifier = ToolResultClassifier()

    assert classifier.diagnose({"status": "error", "error": "Unknown field process_name in schema"})["diagnosis"] == "schema_mismatch"
    assert classifier.diagnose({"status": "executed", "results_count": 0, "metadata": {"error": "index not found: endpoint"}})["diagnosis"] == "wrong_index_or_source"
    no_telemetry = classifier.diagnose({"status": "executed", "results_count": 0, "message": "No telemetry source onboarded for this host"})
    assert no_telemetry["diagnosis"] == "no_telemetry"
    assert no_telemetry["diagnosis_confidence"] == "medium"


def test_tool_result_classifier_classes_core_retry_states():
    classifier = ToolResultClassifier()

    assert classifier.classify({"status": "manual_lookup_required"}) == "manual_required"
    assert classifier.classify({"status": "approval_required"}) == "approval_required"
    assert classifier.classify({"status": "blocked"}) == "blocked_by_policy"
    assert classifier.classify({"status": "not_configured"}) == "backend_unavailable"
    assert classifier.classify({"status": "executed", "results_count": 0}) == "empty_result"
    assert classifier.classify({"status": "executed", "results_count": 1}) == "success_sufficient"


def test_retry_policy_stops_on_block_and_enforces_gap_budget():
    policy = RetryPolicy(max_attempts_per_gap=1)

    assert policy.decide(result_class="blocked_by_policy", gap="process", objective="hunt")["action"] == "stop"
    exhausted = policy.decide(
        result_class="empty_result",
        gap="process",
        objective="hunt",
        retry_state={"attempts": [{"gap": "process", "objective": "hunt"}]},
    )
    assert exhausted["stop_reason"] == "gap_retry_budget_exhausted"


def test_backtracking_engine_produces_safe_fallback_variant():
    plan = BacktrackingEngine().plan_next(
        result={"status": "executed", "results_count": 0},
        coverage_matrix={"blocking_gaps": [{"facet": "process"}]},
        focus="alice",
        objective="hunt missing process",
        retry_state={"attempts": []},
    )

    assert plan["action"] == "retry"
    assert plan["query_variant"]["target_facets"] == ["process"]
    assert "outputlookup" not in plan["query_variant"]["query"].lower()


def test_backtracking_engine_accepts_validated_llm_rewrite_advisory():
    response = json.dumps({
        "candidates": [
            {"backend": "splunk", "query": 'search index=endpoint process_name=* "alice" | head 50', "objective": "Find process facet", "expected_facets": ["process"]}
        ]
    })
    assistant = LLMQueryAssistant(config={"log_hunting": {"llm_query_assist_enabled": True}}, provider=lambda _prompt: response)
    plan = BacktrackingEngine(llm_assistant=assistant).plan_next(
        result={"status": "executed", "results_count": 0, "queries": {"splunk": ["search index=* alice | head 50"]}},
        coverage_matrix={"blocking_gaps": [{"facet": "process"}], "missing_facets": ["process"]},
        focus="alice",
        objective="hunt missing process",
        retry_state={"attempts": []},
    )

    assert plan["action"] == "retry"
    assert plan["llm_rewrite_advisory"]["accepted_count"] == 1
    assert plan["llm_rewrite_advisory"]["accepted_variants"][0]["validation_metadata"]["status"] == "executable"


def test_query_result_evaluator_classifies_remaining_facets():
    evaluation = QueryResultEvaluator().evaluate(
        result={
            "status": "executed",
            "results_count": 1,
            "coverage_matrix": {"covered_facets": ["user"], "missing_facets": ["process"]},
        },
        expected_facets=["user", "process"],
    )

    assert evaluation["result_class"] == "success_partial"
    assert evaluation["remaining_facets"] == ["process"]


def test_full_loop_retry_attempts_improve_coverage_contract():
    state = SimpleNamespace(
        goal="Investigate alice logon",
        investigation_plan={"lane": "log_identity"},
        agentic_explanation={},
        findings=[
            {
                "type": "tool_result",
                "tool": "search_logs",
                "result": {
                    "status": "executed",
                    "mode": "splunk_live",
                    "results_count": 0,
                    "queries": {"splunk": ["search index=auth alice | head 50"]},
                    "coverage_matrix": {"retry_recommended": True, "covered_facets": ["user"], "missing_facets": ["process"], "blocking_gaps": [{"facet": "process"}], "overall_score": 0.25},
                },
            }
        ],
        reasoning_state={"retry_state": {"attempts": []}, "last_investigation_query_plan": {"objective": "hunt", "focus": "alice"}},
    )
    planner = NextActionPlanner(
        get_tool=lambda name: object() if name == "search_logs" else None,
        has_tool_result=lambda _state, _tool: False,
        guess_first_tool=lambda _goal: "search_logs",
        guess_tool_params=lambda _goal: {},
        latest_analyst_message=lambda _state: "",
        latest_focus_candidate=lambda _state: "alice",
        resolve_authoritative_outcome=lambda _state: None,
        simple_chat_has_strong_evidence=lambda _state: False,
        looks_like_artifact_submission=lambda _msg: False,
        build_reasoning_search_request=lambda _state, _questions: {"query": {"splunk": ["search index=endpoint process_name=* alice | head 200"]}, "timerange": "24h", "plan": {"focus": "alice"}},
    )

    decision = planner._retry_log_pivot_decision(state, set(), ["process?"])
    second_coverage = normalize_log_coverage_matrix({"coverage_targets": ["user", "process"], "covered_facets": ["user", "process"], "missing_facets": []})

    assert decision["retry_plan"]["backtrack_plan"]["diagnosis"]["diagnosis"] in ToolResultClassifier.DIAGNOSES
    assert state.reasoning_state["last_log_retry_plan"]["attempt"] == 2
    assert state.reasoning_state["last_log_retry_plan"]["target_facets"] == ["process"]
    assert second_coverage["overall_score"] > 0.25
    assert second_coverage["blocking_gaps"] == []


def test_prompt_renders_compact_retry_and_query_evaluation_summary():
    state = SimpleNamespace(
        investigation_plan={"lane": "log_identity", "lead_profile": "investigator", "primary_entities": []},
        reasoning_state={
            "status": "collecting_evidence",
            "coverage_matrix": {"overall_status": "partial", "overall_score": 0.5},
            "query_attempts": [
                {"result_class": "empty_result", "covered_cells": ["user"], "remaining_gaps": ["process"], "diagnosis": {"diagnosis": "empty_but_query_valid", "reason": "The query was valid but returned no rows.", "diagnosis_confidence": "low"}, "coverage_delta": {"newly_covered_facets": ["user"], "still_missing_facets": ["process"], "score_delta": 0.25}}
            ],
            "retry_state": {"last_decision": {"action": "retry"}, "last_diagnosis": {"diagnosis": "empty_but_query_valid", "reason": "The query was valid but returned no rows.", "diagnosis_confidence": "low"}, "last_coverage_delta": {"newly_covered_facets": ["user"], "still_missing_facets": ["process"]}},
            "last_query_result_evaluation": {"result_class": "empty_result", "remaining_facets": ["process"]},
            "hypotheses": [{"statement": "Credential misuse", "confidence": 0.5, "status": "open"}],
        },
        active_observations=[],
        evidence_quality_summary={},
        agentic_explanation={},
        entity_state={"entities": {}},
        unresolved_questions=[],
    )

    block = PromptComposer().build_reasoning_block(state, is_chat_session=False)

    assert "Latest query attempt: class=empty_result" in block
    assert "Retry state: decision=retry" in block
    assert "Retry diagnosis: empty_but_query_valid confidence=low" in block
    assert "Latest query coverage delta: new=user" in block
    assert "Retry coverage delta: new=user" in block
    assert "Query result evaluation: class=empty_result" in block


def test_next_action_planner_records_policy_stop_on_budget_exhaustion():
    state = SimpleNamespace(
        goal="Investigate alice logon",
        investigation_plan={"lane": "log_identity"},
        agentic_explanation={},
        findings=[
            {
                "type": "tool_result",
                "tool": "search_logs",
                "result": {
                    "status": "executed",
                    "mode": "splunk_live",
                    "results_count": 0,
                    "queries": {"splunk": ["search index=* alice | head 200"]},
                    "coverage_matrix": {"retry_recommended": True, "missing_facets": ["process"], "blocking_gaps": [{"facet": "process"}]},
                },
            }
        ],
        reasoning_state={
            "retry_state": {"attempts": [{"gap": "process", "objective": "hunt"}]},
            "last_investigation_query_plan": {"objective": "hunt"},
        },
    )
    planner = NextActionPlanner(
        get_tool=lambda name: object() if name == "search_logs" else None,
        has_tool_result=lambda _state, _tool: False,
        guess_first_tool=lambda _goal: "search_logs",
        guess_tool_params=lambda _goal: {},
        latest_analyst_message=lambda _state: "",
        latest_focus_candidate=lambda _state: "alice",
        resolve_authoritative_outcome=lambda _state: None,
        simple_chat_has_strong_evidence=lambda _state: False,
        looks_like_artifact_submission=lambda _msg: False,
        build_reasoning_search_request=lambda _state, _questions: {"query": {"splunk": ["search index=* alice process | head 200"]}, "timerange": "24h", "plan": {"focus": "alice"}},
        retry_policy=RetryPolicy(max_attempts_per_gap=1),
    )

    assert planner._retry_log_pivot_decision(state, set(), ["process?"]) is None
    assert state.reasoning_state["last_log_retry_plan"]["stop_reason"] == "gap_retry_budget_exhausted"


def test_next_action_planner_observably_uses_backtracking_for_retry():
    state = SimpleNamespace(
        goal="Investigate alice logon",
        investigation_plan={"lane": "log_identity"},
        agentic_explanation={},
        findings=[
            {
                "type": "tool_result",
                "tool": "search_logs",
                "result": {
                    "status": "executed",
                    "mode": "splunk_live",
                    "results_count": 0,
                    "queries": {"splunk": ["search index=* alice | head 200"]},
                    "coverage_matrix": {"retry_recommended": True, "missing_facets": ["process"], "blocking_gaps": [{"facet": "process"}]},
                },
            }
        ],
        reasoning_state={"retry_state": {"attempts": []}, "last_investigation_query_plan": {"objective": "hunt"}},
    )
    planner = NextActionPlanner(
        get_tool=lambda name: object() if name == "search_logs" else None,
        has_tool_result=lambda _state, _tool: False,
        guess_first_tool=lambda _goal: "search_logs",
        guess_tool_params=lambda _goal: {},
        latest_analyst_message=lambda _state: "",
        latest_focus_candidate=lambda _state: "alice",
        resolve_authoritative_outcome=lambda _state: None,
        simple_chat_has_strong_evidence=lambda _state: False,
        looks_like_artifact_submission=lambda _msg: False,
        build_reasoning_search_request=lambda _state, _questions: {"query": {"splunk": ["search index=* alice | head 200"]}, "timerange": "24h", "plan": {"focus": "alice"}},
    )

    decision = planner._retry_log_pivot_decision(state, set(), ["process?"])

    assert decision["tool"] == "search_logs"
    assert "process_name" in decision["params"]["query"]["splunk"][0]
    assert decision["retry_plan"]["backtrack_plan"]["action"] == "retry"


def test_retry_policy_from_config_honors_runtime_budgets():
    policy = RetryPolicy.from_config(
        {"log_hunting": {"max_attempts_per_gap": 1, "max_attempts_per_objective": 2, "max_attempts_per_session": 3}}
    )

    assert policy.max_attempts_per_gap == 1
    assert policy.max_attempts_per_objective == 2
    assert policy.max_attempts_per_session == 3
    decision = policy.decide(
        result_class="empty_result",
        gap="session",
        objective="auth_linkage",
        retry_state={"attempts": [{"gap": "session", "objective": "auth_linkage"}]},
    )
    assert decision["stop_reason"] == "gap_retry_budget_exhausted"


def test_normalize_log_coverage_matrix_preserves_common_schema_and_extensions():
    matrix = normalize_log_coverage_matrix(
        {
            "coverage_targets": ["user", "host"],
            "covered_facets": ["user"],
            "question_coverage": [{"question": "which host?", "status": "partial"}],
            "entity_coverage": {"alice": {"type": "user", "status": "matched"}},
            "retry_recommended": True,
        }
    )

    assert {"cells", "overall_score", "blocking_gaps", "coverage_status"}.issubset(matrix)
    assert matrix["required_facets"] == ["user", "host"]
    assert matrix["question_coverage"][0]["question"] == "which host?"
    assert matrix["entity_coverage"]["alice"]["status"] == "matched"
    assert matrix["retry_recommended"] is True


def test_log_coverage_vendor_aliases_cover_splunk_and_fortigate_fields():
    matrix = evaluate_log_result_coverage(
        query_plan={"required_facets": ["user", "host", "network"]},
        result={
            "status": "executed",
            "results_count": 1,
            "results": [{"srcip": "10.0.0.5", "dstip": "8.8.8.8", "dst_host": "server-a", "src_user": "alice", "dvc": "fw-1", "devname": "FGT"}],
            "executed_queries": [],
        },
        executed=True,
    )

    assert {"user", "host", "network"}.issubset(set(matrix["covered_facets"]))


def test_coverage_evaluator_adds_hypothesis_required_evidence_gap_and_reduces_it_with_matching_observation():
    hypothesis = {
        "id": "hyp-c2",
        "statement": "Potential C2 beaconing",
        "hypothesis_type": "c2_beaconing",
        "attack_path": ["command_and_control"],
        "required_evidence": [
            {
                "contract_id": "c2_contract",
                "required_observation_types": ["network_event"],
                "required_entities": ["host", "ip"],
                "required_relations": ["connects_to"],
            }
        ],
    }
    empty_matrix = CoverageEvaluator().evaluate(
        lane="network",
        active_observations=[],
        entity_state={"entities": {}, "relationships": []},
        evidence_state={"timeline": []},
        reasoning_state={"hypotheses": [hypothesis]},
    )
    hyp_cell = next(cell for cell in empty_matrix["cells"] if cell["metadata"].get("cell_type") == "hypothesis_required_evidence")
    assert hyp_cell["status"] == "missing"
    assert {"network_event", "host", "ip", "connects_to"}.issubset(set(hyp_cell["missing_fields"]))

    improved_matrix = CoverageEvaluator().evaluate(
        lane="network",
        active_observations=[
            {
                "observation_id": "obs-net-1",
                "tool_name": "search_logs",
                "quality": 0.84,
                "typed_fact": {"type": "network_event", "family": "log", "quality": 0.84},
                "facts": {"host": "WS-12", "dest_ip": "185.220.101.45"},
                "entities": [{"type": "host", "value": "WS-12"}, {"type": "ip", "value": "185.220.101.45"}],
            }
        ],
        entity_state={
            "entities": {
                "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12"},
                "ip:185.220.101.45": {"id": "ip:185.220.101.45", "type": "ip", "value": "185.220.101.45"},
            },
            "relationships": [{"relation": "connects_to", "relation_strength": "explicit"}],
        },
        evidence_state={"timeline": [{"summary": "egress event"}]},
        reasoning_state={"hypotheses": [hypothesis]},
    )
    improved_cell = next(cell for cell in improved_matrix["cells"] if cell["metadata"].get("cell_type") == "hypothesis_required_evidence")
    assert improved_cell["status"] == "covered"
    assert improved_cell["missing_fields"] == []
    assert improved_cell["metadata"]["relation_basis"]["connects_to"] == "explicit"
    assert improved_cell["metadata"]["strongest_relation_basis"] == "explicit"


def test_hypothesis_required_evidence_relation_basis_distinguishes_inferred_and_missing():
    hypothesis = {
        "id": "hyp-c2",
        "statement": "Potential C2 beaconing",
        "hypothesis_type": "c2_beaconing",
        "required_evidence": [
            {
                "contract_id": "c2_contract",
                "required_observation_types": ["network_event"],
                "required_entities": ["host", "ip"],
                "required_relations": ["connects_to"],
            }
        ],
    }
    base_kwargs = {
        "lane": "network",
        "active_observations": [
            {
                "observation_id": "obs-net-1",
                "tool_name": "search_logs",
                "quality": 0.84,
                "typed_fact": {"type": "network_event", "family": "log", "quality": 0.84},
                "entities": [{"type": "host", "value": "WS-12"}, {"type": "ip", "value": "185.220.101.45"}],
            }
        ],
        "entity_state": {"entities": {"h": {"type": "host"}, "i": {"type": "ip"}}, "relationships": [{"relation": "connects_to", "relation_strength": "inferred"}]},
        "evidence_state": {"timeline": []},
        "reasoning_state": {"hypotheses": [hypothesis]},
    }

    inferred = CoverageEvaluator().evaluate(**base_kwargs)
    inferred_cell = next(cell for cell in inferred["cells"] if cell["metadata"].get("cell_type") == "hypothesis_required_evidence")
    assert inferred_cell["status"] == "covered"
    assert inferred_cell["metadata"]["relation_basis"]["connects_to"] == "inferred"

    missing = CoverageEvaluator().evaluate(**{**base_kwargs, "entity_state": {"entities": {"h": {"type": "host"}, "i": {"type": "ip"}}, "relationships": []}})
    missing_cell = next(cell for cell in missing["cells"] if cell["metadata"].get("cell_type") == "hypothesis_required_evidence")
    assert missing_cell["status"] == "partial"
    assert missing_cell["metadata"]["relation_basis"]["connects_to"] == "missing"
    assert "connects_to" in missing_cell["missing_fields"]


def test_evidence_graph_syncs_compact_retry_coverage_and_hypothesis_metadata():
    reasoning_state = {
        "hypotheses": [
            {
                "id": "hyp-c2",
                "statement": "Potential C2 beaconing",
                "hypothesis_type": "c2_beaconing",
                "reason_codes": ["P0_C2_FORTIGATE_BEACON"],
                "audit_trail": [{"event": "confidence_delta", "delta": 0.12}],
                "confidence_delta": 0.12,
                "required_evidence": [],
            }
        ],
        "coverage_matrix": {
            "cells": [
                {
                    "facet": "hypothesis:c2_beaconing:c2_contract",
                    "status": "partial",
                    "confidence": 0.66,
                    "missing_fields": ["connects_to"],
                    "metadata": {
                        "cell_type": "hypothesis_required_evidence",
                        "hypothesis_id": "hyp-c2",
                        "hypothesis_type": "c2_beaconing",
                        "contract_id": "c2_contract",
                        "relation_basis": {"connects_to": "inferred"},
                        "strongest_relation_basis": "inferred",
                    },
                }
            ]
        },
        "query_attempts": [
            {
                "attempt_id": "query-attempt-1",
                "objective": "network pivot",
                "result_class": "success_partial",
                "covered_cells": ["network"],
                "remaining_gaps": ["process"],
                "coverage_delta": {"newly_covered_facets": ["network"], "still_missing_facets": ["process"], "authoritative": False},
            }
        ],
        "retry_audit_events": [
            {
                "event_type": "retry_backtracking_decision",
                "attempt_id": "query-attempt-1",
                "result_class": "success_partial",
                "coverage_delta": {"newly_covered_facets": ["network"], "authoritative": False},
                "diagnosis": {"diagnosis": "empty_but_query_valid"},
            }
        ],
        "hypothesis_events": [
            {
                "event_id": "hyp-event-1",
                "event_type": "confidence_delta",
                "hypothesis_id": "hyp-c2",
                "reason_codes": ["EVIDENCE_GAIN"],
                "summary": "Hypothesis confidence changed after network evidence.",
            }
        ],
    }

    graph = EvidenceGraph().sync_reasoning({}, session_id="sess-graph", reasoning_state=reasoning_state, root_cause_assessment={})
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = graph["edges"]

    assert nodes["hypothesis:hyp-c2"]["reason_codes"] == ["P0_C2_FORTIGATE_BEACON"]
    assert nodes["hypothesis:hyp-c2"]["authoritative"] is False
    assert nodes["coverage:hypothesis:hyp-c2:c2_contract"]["relation_basis"]["connects_to"] == "inferred"
    assert nodes["query-attempt:sess-graph:query-attempt-1"]["coverage_delta"]["authoritative"] is False
    assert nodes["retry-audit:sess-graph:query-attempt-1"]["authoritative"] is False
    assert nodes["hypothesis-event:sess-graph:hyp-event-1"]["authoritative"] is False
    assert any(edge["relation"] == "requires" and edge["basis"] == "hypothesis_required_evidence_coverage" for edge in edges)
    assert any(edge["relation"] == "audits" and edge["basis"] == "retry_backtracking_audit" for edge in edges)
 
from src.agent.entity_resolver import EntityResolver 
 
def test_entity_resolver_does_not_classify_executables_as_domain_iocs(): 
    resolver = EntityResolver() 
    extracted = list(resolver._extract_entities('powershell.exe', 'result.fields.Image')) 
    assert extracted and extracted[0]['type'] == 'process' 
    text_extracted = list(resolver._extract_entities('powershell.exe stage2.exe fields.commandline', 'result.message')) 
    assert not any(item['type'] == 'domain' for item in text_extracted)
