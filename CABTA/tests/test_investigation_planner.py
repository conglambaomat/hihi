import sys
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.investigation_planner import InvestigationPlanner


class _WorkflowRegistry:
    def __init__(self):
        self._items = {
            "ioc-triage": {
                "id": "ioc-triage",
                "name": "IOC Triage",
                "default_agent_profile": "threat_intel_analyst",
                "capabilities": ["ioc-enrichment", "priority-ranking", "analyst-summary"],
                "trigger_examples": ["Investigate whether this IP is malicious"],
            },
            "phishing-investigation": {
                "id": "phishing-investigation",
                "name": "Phishing Investigation",
                "default_agent_profile": "phishing_analyst",
                "capabilities": ["email-forensics", "phishing-analysis", "case-management"],
                "trigger_examples": ["Run phishing investigation on this suspicious email"],
            },
            "forensic-analysis": {
                "id": "forensic-analysis",
                "name": "Forensic Analysis",
                "default_agent_profile": "network_forensics",
                "capabilities": ["evidence-collection", "timeline-reconstruction", "attack-path-analysis"],
                "trigger_examples": ["Run forensic analysis on this host compromise"],
            },
            "full-investigation": {
                "id": "full-investigation",
                "name": "Full Investigation",
                "default_agent_profile": "investigator",
                "capabilities": ["timeline-analysis", "case-investigation"],
                "trigger_examples": ["Run a full investigation"],
            },
        }

    def get_workflow(self, workflow_id):
        return self._items.get(workflow_id)

    def list_workflows(self):
        return list(self._items.values())


def test_build_plan_merges_goal_and_metadata_observables():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate suspicious infrastructure related to callback traffic",
        metadata={
            "observables": ["185.220.101.45", "secure-payroll-check.com"],
            "typed_fact_hints": ["Observed callback beaconing to 185.220.101.45"],
            "accepted_facts": [{"cve": "CVE-2025-12345"}],
        },
    )

    assert "185.220.101.45" in plan["observable_summary"]
    assert "secure-payroll-check.com" in plan["observable_summary"]
    assert "CVE-2025-12345" in plan["observable_summary"]


def test_build_plan_classifies_command_and_control_from_ip_and_fact_hints():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate 185.220.101.45",
        metadata={
            "typed_fact_hints": ["Repeated beacon callback traffic from host WS-12 to 185.220.101.45"],
            "entity_hints": ["host:WS-12", "ip:185.220.101.45"],
        },
    )

    assert plan["lane"] == "ioc"
    assert plan["incident_type"] == "suspected_command_and_control"
    assert any("Pivot from the IP observable" in item for item in plan["first_pivots"])
    assert any(signal["tool"] == "investigate_ioc" for signal in plan["next_action_signals"])
    assert any(
        signal["tool"] == "investigate_ioc" and signal["signal_type"] in {"evidence_gap", "plan_pivot", "hypothesis"}
        for signal in plan["next_action_signals"]
    )


def test_build_plan_classifies_phishing_infrastructure_from_domain_and_delivery_hints():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate secure-payroll-check.com",
        metadata={
            "capability_family": "email_forensics",
            "typed_fact_hints": ["Brand spoof mail delivery referenced secure-payroll-check.com in phishing email"],
        },
    )

    assert plan["lane"] == "email"
    assert plan["incident_type"] == "phishing_or_malicious_email"
    assert any("delivery evidence" in item.lower() for item in plan["evidence_gaps"])
    assert any(signal["tool"] == "analyze_email" for signal in plan["next_action_signals"])


def test_build_plan_uses_workflow_truth_for_ioc_selection():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate whether 185.220.101.45 is malicious",
        metadata={
            "capability_family": "ioc-enrichment",
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert plan["lane"] == "ioc"
    assert plan["workflow_id"] == "ioc-triage"
    assert plan["lead_profile"] == "threat_intel_analyst"


def test_build_plan_uses_workflow_truth_for_email_selection():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate suspicious email from payroll@secure-payroll-check.com with attachment",
        metadata={
            "capability_family": "email-forensics",
            "typed_fact_hints": ["Possible BEC message targeting finance mailbox"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert plan["lane"] == "email"
    assert plan["workflow_id"] == "phishing-investigation"
    assert plan["lead_profile"] == "phishing_analyst"


def test_build_plan_uses_capability_truth_for_workflow_and_incident_type():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Review suspicious attachment execution",
        metadata={
            "agent_profile_id": "malware_analyst",
            "capability_family": "forensics",
            "typed_fact_hints": ["Sandbox execution showed loader behavior for invoice_attachment.exe"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert plan["lane"] == "file"
    assert plan["workflow_id"] == "forensic-analysis"
    assert plan["lead_profile"] == "malware_analyst"
    assert plan["incident_type"] == "malware_or_file_execution"


def test_build_plan_prefers_workflow_truth_profile_when_metadata_profile_missing():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Build forensic timeline for compromised host with suspicious loader execution",
        metadata={
            "capability_family": "timeline-reconstruction",
            "typed_fact_hints": ["Artifact-backed forensic review for compromised host"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert plan["workflow_id"] == "forensic-analysis"
    assert plan["lead_profile"] == "network_forensics"


def test_build_plan_seeds_email_hypotheses_from_typed_facts():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate suspicious finance email",
        metadata={
            "capability_family": "email-forensics",
            "typed_fact_hints": ["Possible business email compromise with invoice spoofing"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert any("business email compromise" in item.lower() for item in plan["initial_hypotheses"])
    assert any("phishing" in item.lower() for item in plan["initial_hypotheses"])


def test_build_plan_seeds_command_and_control_hypothesis_from_fact_hints():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate callback traffic to 185.220.101.45",
        metadata={
            "typed_fact_hints": ["Observed recurring beacon callback from host WS-12"],
            "entity_hints": ["host:WS-12", "ip:185.220.101.45"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert any("command-and-control" in item.lower() for item in plan["initial_hypotheses"])
    assert any("entity linkage" in item.lower() for item in plan["initial_hypotheses"])


def test_build_plan_derives_stopping_conditions_from_typed_evidence_gaps():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate suspicious finance email",
        metadata={
            "capability_family": "email-forensics",
            "typed_fact_hints": ["Need sender and attachment delivery evidence before conclusion"],
            "observables": ["payroll@secure-payroll-check.com"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert any("delivery evidence" in item.lower() or "delivery" in item.lower() for item in plan["stopping_conditions"])
    assert any("primary observable set" in item.lower() for item in plan["stopping_conditions"])


def test_build_plan_derives_escalation_conditions_from_high_risk_typed_facts():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate recurring callback traffic",
        metadata={
            "typed_fact_hints": [
                "Observed command and control beacon callback",
                "Possible business email compromise and invoice spoofing",
            ],
            "entity_hints": ["host:WS-12", "user:alice", "session:S-1"],
        },
        workflow_registry=_WorkflowRegistry(),
    )

    assert any("command-and-control" in item.lower() for item in plan["escalation_conditions"])
    assert any("business email compromise" in item.lower() or "bec" in item.lower() for item in plan["escalation_conditions"])
    assert any("entity linkage" in item.lower() or "host, user, session" in item.lower() for item in plan["escalation_conditions"])


def test_normalize_existing_backfills_incident_type_from_existing_payload_metadata():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Explain the suspicious callback IP",
        existing={
            "goal": "old",
            "lane": "ioc",
            "workflow_id": None,
            "lead_profile": "investigator",
            "primary_entities": ["ip"],
            "observable_summary": ["185.220.101.45"],
            "incident_type": "",
            "evidence_gaps": [],
            "initial_hypotheses": [],
            "first_pivots": [],
            "stopping_conditions": [],
            "escalation_conditions": [],
            "typed_fact_hints": ["Observed command and control beacon traffic to 185.220.101.45"],
        },
    )

    assert plan["goal"] == "Explain the suspicious callback IP"
    assert plan["incident_type"] == "suspected_command_and_control"
    assert plan["next_action_signals"] == []


def test_build_plan_emits_prioritized_next_action_signals_for_log_identity_gap():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate suspicious session activity for alice from 185.220.101.45",
        metadata={
            "typed_fact_hints": [
                "Possible login anomaly with host:WS-12 user:alice session:S-1",
            ],
            "entity_hints": ["host:WS-12", "user:alice", "session:S-1"],
        },
    )

    assert plan["lane"] == "log_identity"
    assert plan["next_action_signals"]
    assert plan["next_action_signals"][0]["tool"] == "search_logs"
    assert plan["next_action_signals"][0]["priority"] >= 95
    assert any(signal["signal_type"] == "hypothesis" for signal in plan["next_action_signals"]) is False


def test_build_plan_emits_fortigate_outbound_triage_contracts():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate FortiGate outbound traffic from WS-12 to 185.220.101.45",
        metadata={
            "typed_fact_hints": [
                "FortiGate firewall observed outbound egress beacon traffic from host:WS-12 to dest_ip:185.220.101.45 over service:https",
            ],
            "entity_hints": ["host:WS-12", "ip:185.220.101.45"],
        },
    )

    assert plan["lane"] == "log_identity"
    assert plan["incident_type"] == "fortigate_outbound_monitoring"
    assert plan["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert any("fortigate egress attribution" in item.lower() for item in plan["evidence_gaps"])
    assert any("validate the strongest observable first" in item.lower() for item in plan["first_pivots"])
    assert any(signal["signal_type"] == "fortigate_outbound" for signal in plan["next_action_signals"])
    fortigate_contract = next(item for item in plan["triage_contracts"] if item["contract_id"] == "fortigate_outbound_monitoring")
    assert fortigate_contract["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert "policy_context" in fortigate_contract["required_fields"]
    assert any("source host" in question.lower() for question in fortigate_contract["analyst_questions"])
    assert any("beacon-like recurrence" in hook.lower() for hook in fortigate_contract["escalation_hooks"])



def test_build_plan_emits_windows_logon_triage_contracts():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate Windows logon failures followed by success for alice on WS-12",
        metadata={
            "typed_fact_hints": [
                "Windows logon monitoring detected EventCode 4625 followed by EventCode 4624 for user:alice on host:WS-12 with logon type 3",
            ],
            "entity_hints": ["host:WS-12", "user:alice", "session:LOGON-22"],
        },
    )

    assert plan["lane"] == "log_identity"
    assert plan["incident_type"] == "windows_logon_monitoring"
    assert plan["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert any("windows logon attribution" in item.lower() for item in plan["evidence_gaps"])
    assert any("validate the strongest observable first" in item.lower() for item in plan["first_pivots"])
    assert any(signal["signal_type"] == "windows_logon" for signal in plan["next_action_signals"])
    windows_contract = next(item for item in plan["triage_contracts"] if item["contract_id"] == "windows_logon_monitoring")
    assert windows_contract["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert "event_sequence" in windows_contract["required_fields"]
    assert any("4625 and 4624" in question for question in windows_contract["analyst_questions"])
    assert any("password spray" in hook.lower() for hook in windows_contract["escalation_hooks"])


def test_build_plan_emits_phishing_email_triage_contracts():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate suspicious finance email from payroll@secure-payroll-check.com",
        metadata={
            "capability_family": "email-forensics",
            "typed_fact_hints": [
                "Possible BEC message with spoofed sender, failed DMARC, and malicious attachment delivery",
            ],
            "observables": ["payroll@secure-payroll-check.com"],
        },
    )

    assert plan["lane"] == "email"
    phishing_contract = next(item for item in plan["triage_contracts"] if item["contract_id"] == "phishing_email_triage")
    assert phishing_contract["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert "auth_results" in phishing_contract["required_fields"]
    assert any("dmarc" in question.lower() for question in phishing_contract["analyst_questions"])
    assert any("impersonation" in hook.lower() or "bec" in hook.lower() for hook in phishing_contract["escalation_hooks"])


def test_build_plan_emits_ioc_triage_contracts():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate whether 185.220.101.45 is malicious infrastructure",
        metadata={
            "capability_family": "ioc-enrichment",
            "typed_fact_hints": [
                "Indicator enrichment shows suspicious callback infrastructure and unresolved host attribution",
            ],
            "entity_hints": ["ip:185.220.101.45", "host:WS-12"],
        },
    )

    assert plan["lane"] == "ioc"
    ioc_contract = next(item for item in plan["triage_contracts"] if item["contract_id"] == "ioc_triage")
    assert ioc_contract["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert "ownership" in ioc_contract["required_fields"]
    assert any("reputation" in question.lower() for question in ioc_contract["analyst_questions"])
    assert any("case linkage" in hook.lower() or "attribution" in hook.lower() for hook in ioc_contract["escalation_hooks"])



def test_normalize_existing_preserves_next_action_signals_shape():
    planner = InvestigationPlanner()

    plan = planner.build_plan(
        "Investigate secure-payroll-check.com",
        existing={
            "goal": "old",
            "lane": "email",
            "workflow_id": "phishing-investigation",
            "lead_profile": "phishing_analyst",
            "primary_entities": ["sender"],
            "observable_summary": ["secure-payroll-check.com"],
            "incident_type": "phishing_or_malicious_email",
            "evidence_gaps": ["Need delivery evidence linking sender and recipient."],
            "initial_hypotheses": ["The email is phishing."],
            "first_pivots": ["Analyze the submitted email first."],
            "next_action_signals": [
                {"tool": "analyze_email", "priority": "100", "reason": "Validate the email first.", "signal_type": "plan_pivot"},
                {"tool": "", "priority": 1, "reason": "skip", "signal_type": "generic"},
            ],
            "stopping_conditions": ["Stop when evidence is sufficient."],
            "escalation_conditions": ["Escalate on high risk."],
        },
    )

    assert plan["goal"] == "Investigate secure-payroll-check.com"
    assert plan["triage_contracts"] == []
    assert plan["deterministic_verdict_owner"] == "CABTA deterministic core"
    assert plan["next_action_signals"] == [
        {
            "tool": "analyze_email",
            "priority": 100,
            "reason": "Validate the email first.",
            "signal_type": "plan_pivot",
        }
    ]