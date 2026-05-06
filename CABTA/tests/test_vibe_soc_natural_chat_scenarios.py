import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_actions import CapabilityAction
from src.agent.clarification_gate import ClarificationGate
from src.agent.parameter_binder import ParameterBinder
from src.agent.preflight_validator import PreflightValidator
from src.agent.agent_state import AgentState
from src.agent.final_answer_gate import FinalAnswerGate
from src.agent.raw_log_parser import analyze_log_artifact
from src.agent.request_understanding import SOCRequestInterpreter
from src.agent.session_response_builder import SessionResponseBuilder


class _ToolLookup:
    def __init__(self, names):
        self.names = set(names)

    def get_tool(self, name):
        return {"name": name} if name in self.names else None


def _protocol(message, tools=("search_logs", "investigate_ioc", "analyze_email", "analyze_malware", "extract_iocs"), context=None):
    task = SOCRequestInterpreter().interpret(message, context or {})
    binder = ParameterBinder()
    validator = PreflightValidator()
    planned = []
    for action_payload in task.actions:
        action = CapabilityAction.from_dict(action_payload)
        binding = binder.bind(action, task)
        preflight = validator.validate(action, binding, task)
        enriched = action.to_dict()
        enriched["binding"] = binding.to_dict()
        enriched["bound_params"] = binding.params
        enriched["preflight"] = preflight.to_dict()
        planned.append(enriched)
    task.actions = planned
    task.pending_clarifications = ClarificationGate().evaluate(task, planned).to_dict().get("payloads", [])
    return task


def _action(task, capability):
    return next(item for item in task.actions if item["capability_id"] == capability)


def test_vietnamese_capability_greeting_routes_to_help_without_evidence_gap_verdict():
    message = "hello bạn có thể làm được gì"
    task = _protocol(message)
    assert task.intent == "config_capability_question"
    assert task.lane == "config"
    assert task.required_capabilities == ["config.capability.explain"]
    assert all(
        requirement.get("blocking") is False
        for requirement in task.objective_contract.get("evidence_requirements", [])
    )

    state = AgentState(session_id="s", goal=message, max_steps=1)
    state.reasoning_state = {"objective_contract": task.objective_contract, "soc_task_state": task.to_dict()}
    gate = FinalAnswerGate().evaluate(
        objective=task.objective_contract,
        state=state,
        draft_answer=SessionResponseBuilder().build_direct_chat_opening_answer(
            prefers_direct_response=True,
            latest_message=message,
        ),
    )
    assert gate.allowed is True
    answer = SessionResponseBuilder().build_direct_chat_opening_answer(
        prefers_direct_response=True,
        latest_message=message,
    )
    assert "IOC triage" in answer
    assert "log/Splunk" in answer
    assert "MALICIOUS" not in answer
    assert "evidence-gap" not in answer.lower()



def test_english_capability_help_routes_to_help_without_investigation_verdict():
    message = "hi what can you do?"
    task = _protocol(message)
    assert task.intent == "config_capability_question"
    assert task.lane == "config"
    assert task.required_capabilities == ["config.capability.explain"]

    state = AgentState(session_id="s", goal=message, max_steps=1)
    state.reasoning_state = {"objective_contract": task.objective_contract, "soc_task_state": task.to_dict()}
    gate = FinalAnswerGate().evaluate(
        objective=task.objective_contract,
        state=state,
        draft_answer="AISA can explain capabilities and ask for an artifact before investigation claims.",
    )
    assert gate.allowed is True



def test_s1_vague_hunt_creates_structured_hunt_not_ioc_sentence():
    task = _protocol("Threat hunt for anything suspicious in our environment from the last 24 hours")
    action = _action(task, "log.search")
    assert task.lane == "network_log_hunt"
    assert action["bound_params"]["query_intent"] == "broad suspicious activity hunt"
    assert "ioc" not in action["bound_params"]


def test_s2_splunk_failed_logons_binds_user_host_timerange_backend():
    task = _protocol("Search Splunk for failed logons followed by success for user alice on host WS-12 yesterday")
    action = _action(task, "log.search")
    params = action["bound_params"]
    assert params["backend"] == "splunk"
    assert params["timerange"] == "yesterday"
    assert any(e["type"] == "user" and e["value"] == "alice" for e in params["entities"])
    assert any(e["type"] == "host" and e["value"] == "WS-12" for e in params["entities"])
    assert params["query_intent"] == "failed logons followed by success"


def test_s3_fortigate_30d_preserves_timerange_and_backend():
    task = _protocol("Check Fortigate historical logs for outbound beaconing from 10.10.5.23 to 185.220.101.45 over the last 30 days")
    action = _action(task, "log.search")
    params = action["bound_params"]
    assert params["backend"] == "fortigate"
    assert params["timerange"] == "30d"
    assert params["requested_timerange"]["requested"] == "last_30_days"
    assert any(e["role"] == "source_ip" and e["value"] == "10.10.5.23" for e in params["entities"])
    assert any(e["role"] == "destination_ip" and e["value"] == "185.220.101.45" for e in params["entities"])
    assert "24h" != params["timerange"]


def test_s4_inline_phishing_email_uses_inline_email_contract():
    task = _protocol("Phishing email From: payroll@example.com Subject: Secure update link https://securecheck.example/login")
    action = _action(task, "email.parse.inline")
    params = action["bound_params"]
    assert params["sender"] == "payroll@example.com"
    assert "https://securecheck.example/login" in params["urls"]
    assert not params.get("file_path")


def test_s5_missing_malware_file_preflight_blocks_execution():
    task = _protocol(r"Analyze malware sample C:\Users\analyst\Downloads\invoice_update.exe but it was not uploaded")
    action = _action(task, "file.analyze.static")
    assert action["bound_params"]["file_path"] == r"C:\Users\analyst\Downloads\invoice_update.exe"
    assert action["bound_params"]["declared_missing"] is True
    assert action["preflight"]["allowed"] is False
    assert action["preflight"]["clarification_required"] is True


def test_s6_ioc_triage_requires_enrichment_not_direct_explain():
    task = _protocol("Triage IOC 185.220.101.45 and tell me if it is malicious with evidence")
    action = _action(task, "ioc.enrich")
    assert task.intent == "ioc_triage"
    assert action["bound_params"]["ioc_value"] == "185.220.101.45"
    assert action["bound_params"]["ioc_type"] == "ip"


def test_s7_ir_approval_creates_governed_action_proposals():
    task = _protocol("Contain host WS-12, disable user alice, block IP 185.220.101.45 if evidence supports it; ask for approval")
    caps = {item["capability_id"] for item in task.actions}
    assert "ir.host.contain.propose" in caps
    assert "ir.user.disable.propose" in caps
    assert "ir.network.block.propose" in caps
    for cap in ("ir.host.contain.propose", "ir.user.disable.propose", "ir.network.block.propose"):
        action = _action(task, cap)
        assert action["preflight"]["allowed"] is False
        assert action["preflight"]["approval_required"] is True


def test_s8_seed_task_persists_task_state_for_followup():
    task = _protocol("Triage IOC 185.220.101.45")
    restored = SOCRequestInterpreter().interpret("What did you find?", {"previous_soc_task_state": task.to_dict()})
    assert restored.conversation_role == "follow_up"
    assert restored.parent_task_id == task.task_id


def test_s9_followup_summary_uses_prior_task_state():
    prior = _protocol("Triage IOC 185.220.101.45")
    task = _protocol("What did you find and what should I do next?", {"previous_soc_task_state": prior.to_dict()})
    assert task.conversation_role == "follow_up"
    assert "case.summarize" in {item["capability_id"] for item in task.actions}
    assert "ioc.extract" not in {item["capability_id"] for item in task.actions}


def test_sentence_leakage_guard_blocks_ioc_and_file_path_full_sentence_params():
    task = _protocol("Triage IOC 185.220.101.45 and explain evidence")
    action = _action(task, "ioc.enrich")
    assert action["bound_params"]["ioc"] != task.raw_request


SPLUNK_STREAM_TCP_LOG = """Analyze this based on Splunk
host=splunk-02 source=stream:tcp sourcetype=stream:tcp src_ip=192.168.250.100 dest_ip=192.168.250.40 dest_port=8089 protocol=tcp transport=ssl ssl_subject_common_name=SplunkServerDefaultCert ssl_issuer_common_name=SplunkCommonCA"""


def test_pasted_splunk_stream_tcp_log_maps_to_inline_network_log_not_email():
    task = _protocol(SPLUNK_STREAM_TCP_LOG)
    facets = {facet for req in task.objective_contract.get("evidence_requirements", []) for facet in req.get("required_facets", [])}

    assert task.lane == "network_log_hunt"
    assert task.intent == "log_artifact_analysis"
    assert "log.analyze.inline" in {item["capability_id"] for item in task.actions}
    assert "email.parse.inline" not in {item["capability_id"] for item in task.actions}
    assert any(item.get("type") == "inline_log_event" for item in task.artifacts)
    assert {"timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "host", "source_sourcetype", "certificate", "backend", "raw_event"}.issubset(facets)
    assert not {"sender", "recipient", "delivery", "url_or_attachment"}.intersection(facets)


def test_pasted_splunk_stream_tcp_coverage_uses_inline_evidence_and_gate_downgrades_malicious():
    from src.agent.coverage import CoverageEvaluator

    task = _protocol(SPLUNK_STREAM_TCP_LOG)
    state = AgentState(session_id="s", goal=SPLUNK_STREAM_TCP_LOG, max_steps=1)
    state.reasoning_state = {"objective_contract": task.objective_contract, "soc_task_state": task.to_dict()}
    coverage = CoverageEvaluator().evaluate(
        active_observations=[],
        entity_state={},
        evidence_state={},
        reasoning_state=state.reasoning_state,
        lane=task.lane,
    )
    state.reasoning_state["coverage_matrix"] = coverage

    assert coverage["lane"] == "network_log_hunt"
    assert "sender" not in coverage.get("missing_facets", [])
    assert "recipient" not in coverage.get("missing_facets", [])
    assert "source_ip" in coverage.get("covered_facets", [])
    assert "destination_port" in coverage.get("covered_facets", [])
    assert "certificate" in coverage.get("covered_facets", [])

    gate = FinalAnswerGate().evaluate(
        objective=task.objective_contract,
        state=state,
        draft_answer="This Splunk stream:tcp SSL log is MALICIOUS.",
    )
    assert gate.allowed is False
    assert gate.provisional_answer
    assert "email" not in " ".join(gate.missing_evidence).lower()
    assert "malicious/clean conclusion" in gate.provisional_answer


def test_final_gate_allows_inconclusive_pasted_sysmon_artifact_without_search_or_correlation():
    sysmon_log = (
        'index=wineventlog sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational '
        'Computer=HR-WIN-001 EventID=1 UtcTime=2026-04-29T08:12:30Z '
        'User=ACME\\trang.nguyen Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
        'ParentImage="C:\\Users\\Public\\stage2.exe" CommandLine="powershell.exe -NoProfile Get-WmiObject" '
        'SourceIp=10.10.20.15 Hashes="SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
    )
    analysis = analyze_log_artifact(raw_log_text=sysmon_log, compiled_input_ref="ci-sysmon")
    state = AgentState(session_id="s", goal=sysmon_log, max_steps=1)
    state.findings = [{"type": "tool_result", "tool": "analyze_log_artifact", "capability": "log.analyze.inline", "result": analysis}]
    state.reasoning_state = {
        "structured_verdict": analysis["structured_verdict"],
        "coverage_matrix": {"covered_facets": ["host", "process"], "missing_facets": ["file_path"]},
        "soc_task_state": {"artifacts": [{"type": "inline_log_event", "fields": analysis["parsed_fields"]}]},
    }
    objective = {
        "contract_id": "obj-sysmon",
        "execution_mode": "strict_production",
        "capabilities_required": ["log.analyze.inline", "log.search", "findings.correlate"],
        "require_provenance": True,
    }

    gate = FinalAnswerGate().evaluate(
        objective=objective,
        state=state,
        draft_answer="The pasted Sysmon event was parsed. It is inconclusive; a single pasted log cannot prove malicious or clean status.",
    )

    assert gate.allowed is True
    assert gate.status == "allowed"
    assert gate.mode == "pasted_log_artifact_inconclusive_allowed"
    assert gate.structured_verdict["scope"] == "pasted_log_artifact"
    assert not gate.blocking_reasons
    assert "file_path" in gate.missing_evidence
