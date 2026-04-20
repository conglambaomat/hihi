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