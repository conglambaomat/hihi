from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_resolver import CapabilityResolver
from src.agent.final_answer_gate import FinalAnswerGate
from src.agent.next_action_planner import NextActionPlanner
from src.agent.objective_model import ObjectiveModelBuilder
from src.agent.request_understanding import RequestUnderstandingExtractor


class _ToolLookup:
    def __init__(self, names):
        self.names = set(names)

    def get_tool(self, name):
        return {"name": name} if name in self.names else None


def _planner(tool_names):
    lookup = _ToolLookup(tool_names)
    return NextActionPlanner(
        get_tool=lookup.get_tool,
        has_tool_result=lambda _state, _tool: False,
        guess_first_tool=lambda _goal: "investigate_ioc",
        guess_tool_params=lambda goal: {"ioc": "8.8.8.8", "file_path": goal},
        latest_analyst_message=lambda state: state.goal,
        latest_focus_candidate=lambda _state: None,
        resolve_authoritative_outcome=lambda _state: None,
        simple_chat_has_strong_evidence=lambda _state: False,
        looks_like_artifact_submission=lambda _message: False,
        build_reasoning_search_request=lambda state, _questions: {
            "query": f"search {state.goal}",
            "timerange": (state.reasoning_state.get("objective_contract", {}) or {}).get("effective_timerange", "24h"),
            "reasoning": "collect requested log evidence",
        },
    )


def _understanding_and_contract(message: str):
    extractor = RequestUnderstandingExtractor()
    understanding = extractor.extract(message)
    contract = ObjectiveModelBuilder().build(understanding)
    return understanding, contract.to_dict()


def test_phase5_splunk_fortigate_threat_hunt_is_log_capability_with_historical_timerange_and_gate_blocks_unsupported_final():
    understanding, contract = _understanding_and_contract(
        "Threat hunt historical Splunk FortiGate firewall logs for outbound beaconing from 10.1.2.3"
    )
    state = SimpleNamespace(
        goal=understanding.raw_text,
        findings=[],
        agentic_explanation={},
        reasoning_state={"objective_contract": contract},
        investigation_plan={
            "lane": "log_identity",
            "next_action_signals": [
                {
                    "capability": "log.search",
                    "capability_id": "log.search",
                    "tool": "search_logs",
                    "reason": "Collect SIEM/firewall evidence before any final answer.",
                    "priority": 100,
                }
            ],
        },
    )

    decision = _planner(["search_logs", "investigate_ioc"]).reasoning_guided_next_action(state)
    gate = FinalAnswerGate().evaluate(objective=contract, state=state, draft_answer="The host is clean.")

    assert understanding.domain == "log_security"
    assert contract["effective_timerange"] == "historical"
    assert decision["action"] == "use_capability"
    assert decision["tool"] == "search_logs"
    assert decision["capability_id"] == "log.search"
    assert decision["params"]["timerange"] == "historical"
    assert decision["tool"] != "investigate_ioc"
    assert gate.allowed is False
    assert "cannot support a final verdict" in gate.provisional_answer


def test_phase5_phishing_email_maps_to_email_analyze_without_splunk_requirement():
    understanding, contract = _understanding_and_contract(
        "Analyze this phishing email from payroll@example.com and inspect SPF DKIM DMARC headers"
    )
    resolver = CapabilityResolver(get_tool=_ToolLookup(["analyze_email", "search_logs"]).get_tool)
    email_resolution = resolver.resolve("email.analyze", objective=contract)

    assert understanding.domain == "email"
    assert contract["capabilities_required"][0] == "email.analyze"
    assert "log.search" not in contract["capabilities_required"]
    assert "splunk" not in contract["requested_backends"]
    assert email_resolution.availability == "available"
    assert email_resolution.selected_tool == "analyze_email"


def test_phase5_email_compromise_log_request_can_require_log_evidence():
    understanding, contract = _understanding_and_contract(
        "Check Splunk logs for compromise evidence after the phishing email delivery"
    )

    assert understanding.domain == "log_security"
    assert "log.search" in contract["capabilities_required"]
    assert "splunk" in contract["requested_backends"]


def test_phase5_malware_file_request_maps_to_static_file_analysis():
    understanding, contract = _understanding_and_contract(
        "Analyze suspicious malware file invoice_payload.exe statically and report indicators"
    )
    resolver = CapabilityResolver(get_tool=_ToolLookup(["analyze_malware", "investigate_ioc"]).get_tool)
    resolution = resolver.resolve("file.analyze.static", objective=contract)

    assert understanding.domain == "file"
    assert "file.analyze.static" in contract["capabilities_required"]
    assert resolution.availability == "available"
    assert resolution.selected_tool == "analyze_malware"


def test_phase5_vague_request_avoids_default_ioc_when_no_observable():
    understanding, contract = _understanding_and_contract("Help")
    state = SimpleNamespace(
        goal="Help",
        findings=[],
        agentic_explanation={},
        reasoning_state={"objective_contract": contract},
        investigation_plan={"lane": "general", "next_action_signals": []},
    )

    decision = _planner(["investigate_ioc"]).reasoning_guided_next_action(state)

    assert understanding.intent == "clarify_request"
    assert "request_is_vague" in understanding.uncertainty
    assert "ioc.enrich" not in contract["capabilities_required"]
    assert decision is None


def test_phase5_ir_containment_maps_to_approval_request_and_never_unsafe_execution():
    understanding, contract = _understanding_and_contract(
        "Contain and isolate host win-7 immediately if it is compromised"
    )
    resolver = CapabilityResolver(get_tool=_ToolLookup(["search_logs", "investigate_ioc"]).get_tool)
    bridged = resolver.decision_to_tool_action({"action": "use_capability", "capability": "ir.approval.request"}, objective=contract)

    assert understanding.domain == "incident_response"
    assert "ir.approval.request" in contract["capabilities_required"]
    assert "approval_required" in contract["approval_requirements"]
    assert bridged["action"] == "degraded_capability"
    assert bridged["availability"] == "unavailable"
    assert "investigate_ioc" not in str(bridged)


def test_phase5_config_runtime_capability_question_is_direct_and_avoids_analysis_tools():
    understanding, contract = _understanding_and_contract(
        "What Splunk and malware analysis capabilities are configured and available?"
    )
    state = SimpleNamespace(reasoning_state={"objective_contract": contract}, findings=[])
    gate = FinalAnswerGate().evaluate(
        objective=contract,
        state=state,
        draft_answer="AISA can explain configured capabilities and degraded integrations.",
    )

    assert understanding.intent == "config_capability_question"
    assert contract["capabilities_required"] == ["config.capability.explain"]
    assert "file.analyze.static" not in contract["capabilities_required"]
    assert "ioc.enrich" not in contract["capabilities_required"]
    assert gate.allowed is True
    assert gate.mode == "direct_or_explanation_allowed"


def test_phase5_missing_log_integration_is_explicit_and_does_not_fallback_to_ioc_tool():
    _, contract = _understanding_and_contract("Threat hunt Splunk FortiGate historical firewall logs")
    resolver = CapabilityResolver(get_tool=_ToolLookup(["investigate_ioc"]).get_tool)
    bridged = resolver.decision_to_tool_action({"action": "use_capability", "capability": "log.search"}, objective=contract)

    assert bridged["action"] == "degraded_capability"
    assert bridged["capability_id"] == "log.search"
    assert bridged["availability"] == "degraded"
    assert "No compatible tool" in bridged["degradation_reason"]
    assert "tool" not in bridged
