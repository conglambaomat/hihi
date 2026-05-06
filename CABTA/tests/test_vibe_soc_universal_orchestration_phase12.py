import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_resolver import CapabilityResolver
from src.agent.investigation_planner import InvestigationPlanner
from src.agent.request_understanding import RequestUnderstandingExtractor


class _ToolLookup:
    def __init__(self, names):
        self.names = set(names)

    def get_tool(self, name):
        return {"name": name} if name in self.names else None


def test_request_understanding_splunk_fortigate_threat_hunt_maps_to_log_search_historical():
    extractor = RequestUnderstandingExtractor()

    understanding = extractor.extract(
        "Threat hunt historical Splunk FortiGate firewall outbound logs for beacon evidence from 10.1.2.3"
    )
    contract = extractor.objective_builder.build(understanding)

    assert understanding.intent == "threat_hunt"
    assert understanding.domain == "log_security"
    assert "splunk" in understanding.requested_backends
    assert "fortigate" in understanding.requested_backends
    assert "log.search" in understanding.capabilities_required
    assert understanding.constraints["historical_scope_requested"] is True
    assert contract.effective_timerange == "historical"
    assert "log.search" in contract.capabilities_required


def test_request_understanding_phishing_email_maps_to_email_analyze():
    understanding = RequestUnderstandingExtractor().extract(
        "Analyze this phishing email from payroll@example.com and check SPF DKIM DMARC"
    )

    assert understanding.intent == "phishing_email_analysis"
    assert understanding.domain == "email"
    assert "email.analyze" in understanding.capabilities_required


def test_request_understanding_malware_file_maps_to_static_file_analysis():
    understanding = RequestUnderstandingExtractor().extract(
        "Analyze suspicious malware file invoice_payload.exe statically before any sandboxing"
    )

    assert understanding.intent == "malware_file_analysis"
    assert understanding.domain == "file"
    assert "file.analyze.static" in understanding.capabilities_required


def test_capability_resolver_maps_capability_to_tool_and_bridges_use_capability():
    resolver = CapabilityResolver(get_tool=_ToolLookup(["search_logs", "investigate_ioc"]).get_tool)
    objective = {
        "summary": "hunt Splunk logs for FortiGate egress",
        "effective_timerange": "historical",
        "timerange": {"effective": "historical"},
    }

    resolution = resolver.resolve("log.search", objective=objective)
    bridged = resolver.decision_to_tool_action(
        {"action": "use_capability", "capability": "log.search", "params": {"max_results": 50}},
        objective=objective,
    )

    assert resolution.availability == "available"
    assert resolution.selected_tool == "search_logs"
    assert bridged["action"] == "use_tool"
    assert bridged["tool"] == "search_logs"
    assert bridged["capability_id"] == "log.search"
    assert bridged["params"]["timerange"] == "historical"
    assert bridged["params"]["max_results"] == 50


def test_capability_resolver_degrades_without_ioc_fallback_for_missing_log_search():
    resolver = CapabilityResolver(get_tool=_ToolLookup(["investigate_ioc"]).get_tool)

    bridged = resolver.decision_to_tool_action({"action": "use_capability", "capability": "log.search"})

    assert bridged["action"] == "degraded_capability"
    assert bridged["capability_id"] == "log.search"
    assert bridged["availability"] == "degraded"
    assert "search_logs" not in bridged.get("tool", "")


def test_investigation_planner_signals_include_capability_fields_and_preserve_tool_fields():
    plan = InvestigationPlanner().build_plan(
        "Threat hunt FortiGate outbound Splunk logs for historical beaconing",
        metadata={"typed_fact_hints": ["fortigate outbound firewall historical splunk hunt"]},
    )

    signals = plan["next_action_signals"]
    assert any(signal["tool"] == "search_logs" for signal in signals)
    log_signal = next(signal for signal in signals if signal["tool"] == "search_logs")
    assert log_signal["capability"] == "log.search"
    assert log_signal["capability_id"] == "log.search"
    assert "reason" in log_signal
