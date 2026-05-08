from src.agent.model_led_planner import (
    ModelLedInvestigationPlan,
    ModelLedPlanVerifier,
    ModelPlannerContext,
)
from src.agent.prompt_composer import PromptComposer
from src.agent.provider_chat_gateway import ProviderChatGateway
from src.agent.adaptive_dag import AdaptiveDAGController, AdaptiveDAGTrigger
from src.agent.investigation_dag import InvestigationDAG


def test_model_led_plan_schema_and_verifier_allows_known_capability_step():
    plan = ModelLedInvestigationPlan.from_dict(
        {
            "planning_intent": "test_next_gap",
            "soc_lane": "log_hunt",
            "hypotheses_to_test": ["hypothesis:0"],
            "evidence_gaps": ["process lineage"],
            "proposed_steps": [
                {
                    "step_type": "capability_action",
                    "capability_id": "log.search",
                    "tool_name": "search_logs",
                    "params": {"query": "process lineage", "timerange": "24h"},
                    "evidence_gap_refs": ["process lineage"],
                    "hypothesis_refs": ["hypothesis:0"],
                    "expected_evidence": ["process execution event"],
                }
            ],
            "expected_evidence": ["process execution event"],
            "stop_conditions": ["gap covered"],
        }
    )
    verifier = ModelLedPlanVerifier(
        get_tool=lambda name: object() if name == "search_logs" else None,
        capability_exists=lambda capability: capability == "log.search",
    )
    result = verifier.verify(
        plan,
        ModelPlannerContext(
            objective="investigate alert",
            coverage_gaps=["process lineage"],
            hypotheses=[{"id": "hypothesis:0", "statement": "suspicious process"}],
        ),
    )

    assert plan.schema_version == "model-led-investigation-plan/v1"
    assert result.status == "allowed"
    assert result.allowed_steps[0]["capability_id"] == "log.search"


def test_model_led_verifier_blocks_unknown_tool_and_final_without_evidence():
    plan = {
        "planning_intent": "finish",
        "proposed_steps": [
            {"step_type": "tool_call", "tool_name": "made_up_tool", "params": {}},
            {"step_type": "final_answer", "params": {}},
        ],
    }
    result = ModelLedPlanVerifier(get_tool=lambda name: None).verify(plan, ModelPlannerContext(objective="x"))

    assert result.status == "blocked"
    assert "unknown_tool:made_up_tool" in result.blocked_reasons
    assert "final_answer_evidence_gate_not_satisfied" in result.blocked_reasons


def test_model_planner_prompt_contains_investigation_board_and_no_cot_instruction():
    payload = PromptComposer().build_model_planner_prompt(
        {
            "objective": "investigate suspicious login",
            "current_dag": {"summary": {"ready_node_ids": ["n1"]}},
            "coverage_gaps": ["source ip reputation"],
            "available_tools": [{"name": "search_logs"}],
            "policy_boundaries": ["no chain-of-thought"],
        }
    )

    assert payload["prompt_mode"] == "model_led_planning"
    assert "INVESTIGATION_BOARD_JSON" in payload["user_prompt"]
    assert "Do not reveal chain-of-thought" in payload["system_prompt"]
    assert payload["messages"][0]["role"] == "system"


def test_provider_gateway_builds_model_led_planning_json_request():
    request = ProviderChatGateway().build_model_planning_request(
        provider_name="router",
        messages=[{"role": "user", "content": "plan"}],
        prompt_envelope={"user_intent": {"mode": "model_led_planning"}},
    )

    assert request["mode"] == "model_led_planning"
    assert request["intent"] == "model_led_planning"
    assert request["response_format"] == {"type": "json_object"}
    assert request["temperature"] > 0
    assert request["tool_choice_allowed"] is False


def test_adaptive_dag_accepts_model_led_planner_source():
    dag = InvestigationDAG(task_ref="task", objective_ref="objective")
    result = AdaptiveDAGController().handle_trigger(
        dag,
        AdaptiveDAGTrigger(
            trigger_type="model_led_planner",
            source="model_led_planner",
            reason="model proposed log search",
            evidence={
                "capability_id": "log.search",
                "allowed_tools": ["search_logs"],
                "params": {"query": "failed login", "timerange": "24h"},
                "model_led_plan_id": "plan-1",
                "model_led_step_id": "step-1",
                "model_led_dedupe_key": "dedupe-1",
            },
        ),
    )

    assert result["applied"] is True
    node = result["dag"]["nodes"][-1]
    assert node["adaptive_metadata"]["proposal_source"] == "model_led_planner"
    assert node["adaptive_metadata"]["model_led_plan_id"] == "plan-1"


def _verify_step(step):
    return ModelLedPlanVerifier(get_tool=lambda name: object()).verify(
        {"planning_intent": "continue", "proposed_steps": [step]},
        ModelPlannerContext(objective="investigate", coverage_gaps=["gap"]),
    )


def test_model_led_verifier_allows_safe_capability_alias():
    result = _verify_step({
        "step_type": "capability_action",
        "capability_id": "siem search",
        "params": {"query": "failed login", "timerange": "24h", "backend": "splunk"},
    })

    assert result.status == "allowed"
    assert result.allowed_steps[0]["resolved_capability"] == "log.search"
    assert result.allowed_steps[0]["resolved_tool"] == "search_logs"


def test_model_led_verifier_blocks_hallucinated_capability_tool():
    result = _verify_step({
        "step_type": "tool_call",
        "capability_id": "quantum.reverse.shell",
        "tool_name": "hack_the_planet",
        "params": {"target": "host"},
    })

    assert result.status == "blocked"
    assert any("unknown_capability" in reason or "unknown_tool" in reason for reason in result.blocked_reasons)
    assert result.step_verifications[0]["blocked_reasons"]


def test_model_led_verifier_requires_approval_for_containment_alias():
    result = _verify_step({
        "step_type": "capability_action",
        "capability_id": "contain host",
        "params": {"target": "WS-12", "evidence_refs": ["evt-1"]},
    })

    assert result.status == "needs_approval"
    assert result.needs_approval[0]["resolved_capability"] == "ir.host.contain.propose"
    assert result.step_verifications[0]["approval_required"] is True
    assert "ir_or_containment_action" in result.step_verifications[0]["risk_reasons"]


def test_model_led_verifier_blocks_broad_unbounded_log_query():
    result = _verify_step({
        "step_type": "capability_action",
        "capability_id": "log.search",
        "params": {"query": "*", "timerange": "all", "backend": "splunk"},
    })

    assert result.status == "blocked"
    assert any("Unbounded log query" in reason for reason in result.blocked_reasons)
    assert "broad_or_unbounded_hunt" in result.step_verifications[0]["risk_reasons"]


def test_model_led_verifier_allows_bounded_read_only_log_search_and_records_metadata():
    result = _verify_step({
        "step_type": "capability_action",
        "capability_id": "log.search",
        "params": {"query": "src_ip=10.0.0.5", "timerange": "24h", "backend": "splunk"},
    })

    assert result.status == "allowed"
    meta = result.step_verifications[0]
    assert meta["resolved_capability"] == "log.search"
    assert meta["resolved_tool"] == "search_logs"
    assert meta["approval_required"] is False
    assert meta["risk_level"] == "low"
    assert meta["policy_reasons"] == []
    assert meta["blocked_reasons"] == []


def test_model_led_verifier_flags_sandbox_and_external_enrichment_risk():
    sandbox = _verify_step({
        "step_type": "capability_action",
        "capability_id": "sandbox analysis",
        "params": {"file_path": "/tmp/sample.exe"},
    })
    external = _verify_step({
        "step_type": "capability_action",
        "capability_id": "ioc.enrich",
        "title": "external enrichment via VirusTotal",
        "params": {"observable": "1.2.3.4"},
    })

    assert sandbox.status in {"needs_approval", "blocked"}
    assert "sandbox_execution_or_submission" in sandbox.step_verifications[0]["risk_reasons"]
    assert external.status == "needs_approval"
    assert "external_network_or_submission" in external.step_verifications[0]["risk_reasons"]


def test_capability_descriptor_is_source_of_truth_for_alias_and_risk_metadata():
    verifier = ModelLedPlanVerifier(get_tool=lambda name: object())
    descriptor = verifier.capability_resolver.ontology.find_by_alias("siem search")

    assert descriptor.capability_id == "log.search"
    assert "siem search" in descriptor.all_aliases()
    assert descriptor.read_only is True
    assert descriptor.approval_required is False

    result = _verify_step({
        "step_type": "capability_action",
        "capability_id": "siem search",
        "params": {"query": "failed login", "timerange": "24h", "backend": "splunk"},
    })

    metadata = result.step_verifications[0]["capability_metadata"]
    assert metadata["capability_id"] == "log.search"
    assert metadata["risk_profile"]["read_only"] is True
    assert metadata["risk_profile"]["approval_required"] is False


def test_capability_descriptor_marks_containment_and_sandbox_approval():
    verifier = ModelLedPlanVerifier(get_tool=lambda name: object())
    containment = verifier.capability_resolver.ontology.find_by_alias("contain host")
    sandbox = verifier.capability_resolver.ontology.find_by_alias("detonate file")

    assert containment.capability_id == "ir.host.contain.propose"
    assert containment.approval_required is True
    assert containment.destructive is True
    assert "ir_or_containment_action" in containment.risk_reasons
    assert sandbox.capability_id == "file.analyze.sandbox"
    assert sandbox.approval_required is True
    assert sandbox.external_network is True
    assert "sandbox_execution_or_submission" in sandbox.risk_reasons
