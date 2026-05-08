"""Capability ontology for additive objective/capability-first orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolContract:
    tool_name: str
    capability: str
    input_schema: Dict[str, Any]
    output_facets: List[str]
    evidence_role: str
    supports_timerange: bool = False
    provider: str = "local"
    requires_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CapabilityDescriptor:
    capability_id: str
    description: str
    domains: List[str]
    required_inputs: List[str]
    output_facets: List[str]
    compatible_tools: List[ToolContract] = field(default_factory=list)
    optional_inputs: List[str] = field(default_factory=list)
    evidence_role: str = "supporting_observation"
    degraded_allowed: bool = True
    aliases: List[str] = field(default_factory=list)
    natural_language_aliases: List[str] = field(default_factory=list)
    model_aliases: List[str] = field(default_factory=list)
    risk_level: str = "low"
    risk_reasons: List[str] = field(default_factory=list)
    approval_required: bool = False
    approval_policy: Dict[str, Any] = field(default_factory=dict)
    approval_triggers: List[str] = field(default_factory=list)
    policy_tags: List[str] = field(default_factory=list)
    safety_tags: List[str] = field(default_factory=list)
    read_only: bool = True
    destructive: bool = False
    external_network: bool = False
    broad_scope: bool = False
    schema_version: str = "capability-descriptor/v2"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["compatible_tools"] = [item.to_dict() for item in self.compatible_tools]
        payload["all_aliases"] = self.all_aliases()
        payload["risk_profile"] = self.risk_profile()
        return payload

    def all_aliases(self) -> List[str]:
        values = [self.capability_id, *self.aliases, *self.natural_language_aliases, *self.model_aliases]
        return list(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))

    def risk_profile(self) -> Dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "risk_reasons": list(self.risk_reasons),
            "approval_required": self.approval_required,
            "approval_policy": dict(self.approval_policy),
            "approval_triggers": list(self.approval_triggers),
            "policy_tags": list(self.policy_tags),
            "safety_tags": list(self.safety_tags),
            "read_only": self.read_only,
            "destructive": self.destructive,
            "external_network": self.external_network,
            "broad_scope": self.broad_scope,
        }


CapabilityContract = CapabilityDescriptor


class CapabilityOntology:
    """In-memory registry of capability contracts and compatible tool adapters."""

    def __init__(self, capabilities: Optional[List[CapabilityContract]] = None):
        self._capabilities: Dict[str, CapabilityContract] = {}
        initial = default_capability_contracts() if capabilities is None else capabilities
        for capability in initial:
            self.register_capability(capability)

    def register_capability(self, capability: CapabilityContract) -> None:
        self._capabilities[capability.capability_id] = capability

    def register_tool_contract(self, contract: ToolContract) -> None:
        capability = self._capabilities.get(contract.capability)
        if capability is None:
            capability = CapabilityContract(
                capability_id=contract.capability,
                description=f"Dynamic capability {contract.capability}",
                domains=[],
                required_inputs=[],
                output_facets=list(contract.output_facets),
                compatible_tools=[],
            )
            self.register_capability(capability)
        capability.compatible_tools.append(contract)

    def get(self, capability_id: str) -> Optional[CapabilityContract]:
        return self._capabilities.get(str(capability_id or "").strip())

    def find_by_alias(self, value: str) -> Optional[CapabilityContract]:
        key = _alias_key(value)
        if not key:
            return None
        if key in self._capabilities:
            return self._capabilities[key]
        for capability in self._capabilities.values():
            if key in {_alias_key(item) for item in capability.all_aliases()}:
                return capability
        return None

    def capabilities_for(self, objective: Any) -> List[CapabilityContract]:
        capability_ids = list(getattr(objective, "capabilities_required", []) or [])
        if not capability_ids and isinstance(objective, dict):
            capability_ids = list(objective.get("capabilities_required") or [])
        return [self._capabilities[item] for item in capability_ids if item in self._capabilities]

    def all(self) -> List[CapabilityContract]:
        return list(self._capabilities.values())


def _alias_key(value: str) -> str:
    return str(value or "").strip().lower().replace("_", " ").replace("-", " ")


def _tool(tool_name: str, capability: str, facets: List[str], *, supports_timerange: bool = False, category: str = "analysis", requires_approval: bool = False) -> ToolContract:
    return ToolContract(
        tool_name=tool_name,
        capability=capability,
        input_schema={"type": "object", "additionalProperties": True},
        output_facets=facets,
        evidence_role=category,
        supports_timerange=supports_timerange,
        provider="local",
        requires_approval=requires_approval,
    )


def _capability(*args: Any, **kwargs: Any) -> CapabilityContract:
    return CapabilityContract(*args, **kwargs)


def default_capability_contracts() -> List[CapabilityContract]:
    return [
        _capability(
            capability_id="log.search",
            description="Search security logs, SIEM data, or firewall telemetry for bounded evidence.",
            domains=["network_log_hunt", "log_security", "incident_response"],
            required_inputs=["query_or_entities", "timerange"],
            output_facets=["timestamp", "source_ip", "destination_ip", "action", "device", "raw_event", "backend", "source", "destination", "events"],
            compatible_tools=[_tool("search_logs", "log.search", ["timestamp", "source_ip", "destination_ip", "action", "raw_event", "backend", "events", "coverage", "timerange"], supports_timerange=True)],
            optional_inputs=["backend", "index", "sourcetype", "limit"],
            evidence_role="primary_observation",
            aliases=["splunk.search", "search_logs"],
            natural_language_aliases=["siem search", "log hunt", "search logs", "splunk search"],
            model_aliases=["related event search", "query logs", "hunt logs"],
            risk_reasons=["read_only_bounded_log_access"],
            policy_tags=["requires_timerange", "bounded_scope"],
            safety_tags=["read_only", "no_mutation"],
        ),
        _capability("log.analyze.inline", "Analyze a pasted raw log event as local inline evidence without requiring live SIEM access.", ["network_log_hunt", "log_security"], ["raw_log_event"], ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "certificate", "backend", "raw_event"], [_tool("analyze_log_artifact", "log.analyze.inline", ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "backend", "raw_event"])], optional_inputs=["backend", "source", "sourcetype"], evidence_role="primary_observation", aliases=["analyze_log_artifact"], natural_language_aliases=["inline log analysis", "parse log event"], safety_tags=["read_only", "local_only"]),
        _capability("ioc.enrich", "Enrich an observable with deterministic threat intelligence.", ["ioc", "log_security", "email", "file"], ["observable"], ["reputation", "ownership", "sightings"], [_tool("investigate_ioc", "ioc.enrich", ["reputation", "verdict", "sources"], category="threat_intel")], aliases=["investigate_ioc"], natural_language_aliases=["ioc enrichment", "external enrichment", "threat intel lookup", "reputation lookup"], model_aliases=["observable reputation", "ti lookup"], risk_level="medium", risk_reasons=["external_network_or_submission"], approval_triggers=["external_submission", "unapproved_external_network"], policy_tags=["threat_intel", "external_lookup"], safety_tags=["read_only"], external_network=True),
        _capability("email.parse.inline", "Parse inline email text supplied in chat without pretending it is a local file.", ["email"], ["raw_email_text_or_sender_url"], ["sender", "recipient", "subject", "urls", "headers", "body"], [], aliases=["parse email"], natural_language_aliases=["inline email parse", "email text parse"], safety_tags=["read_only", "local_only"]),
        _capability("email.analyze", "Analyze email artifacts, headers, sender auth, URLs, and attachments.", ["email"], ["email_artifact_or_text"], ["headers", "sender", "auth_results", "urls", "attachments"], [_tool("analyze_email", "email.analyze", ["headers", "urls", "attachments", "verdict"])], aliases=["analyze_email"], natural_language_aliases=["email analysis", "phishing email analysis", "analyze email"], risk_reasons=["artifact_read_only_analysis"], policy_tags=["email", "artifact_analysis"], safety_tags=["read_only"]),
        _capability("file.analyze.static", "Perform static file or malware artifact analysis.", ["file"], ["file_or_hash"], ["file_identity", "hashes", "strings", "static_indicators"], [_tool("analyze_malware", "file.analyze.static", ["file_metadata", "indicators", "verdict"])], aliases=["analyze_malware"], natural_language_aliases=["static file analysis", "malware static analysis", "analyze file"], risk_reasons=["artifact_read_only_analysis"], policy_tags=["file", "static_analysis"], safety_tags=["read_only", "no_execution"]),
        _capability("file.analyze.sandbox", "Analyze file behavior through sandbox-backed evidence when available.", ["file"], ["file_or_hash"], ["behavior", "network", "process", "persistence"], [_tool("analyze_malware", "file.analyze.sandbox", ["behavior", "network", "process"], category="sandbox", requires_approval=True)], aliases=["sandbox.run"], natural_language_aliases=["sandbox analysis", "detonate file", "dynamic analysis"], model_aliases=["run sample in sandbox"], risk_level="high", risk_reasons=["sandbox_execution_or_submission", "external_network_or_submission"], approval_required=True, approval_policy={"approval_required": True, "mode": "analyst_before_execution"}, approval_triggers=["sandbox_execution", "artifact_submission", "external_network"], policy_tags=["sandbox", "dynamic_analysis"], safety_tags=["execution", "external_submission"], read_only=False, external_network=True),
        _capability("ioc.extract", "Extract observables from analyst text or artifacts.", ["general", "email", "file", "ioc"], ["text_or_artifact"], ["observables", "observable_types"], [_tool("extract_iocs", "ioc.extract", ["observables", "observable_types"])], aliases=["extract_iocs"], natural_language_aliases=["extract iocs", "observable extraction"], safety_tags=["read_only", "local_only"]),
        _capability("case.summarize", "Summarize prior task or case evidence without starting extraction.", ["case", "case_follow_up"], ["task_ref"], ["case_summary", "evidence_refs"], [], aliases=["summarize case"], safety_tags=["read_only"]),
        _capability("correlate.findings", "Correlate findings across observations.", ["general", "log_security", "email", "file", "ioc"], ["observations"], ["linked_entities", "timeline"], [_tool("correlate_findings", "correlate.findings", ["linked_entities", "timeline"])], aliases=["correlate_findings", "findings.correlate"], natural_language_aliases=["correlate findings", "link findings", "build timeline"], safety_tags=["read_only", "local_only"]),
        _capability("findings.correlate", "Correlate findings across observations.", ["general", "log_security", "email", "file", "ioc"], ["observations"], ["linked_entities", "timeline"], [], aliases=["correlate.findings"], natural_language_aliases=["correlate findings"], safety_tags=["read_only", "local_only"]),
        _capability("threat_intel.search", "Search threat-intelligence context for a topic or observable.", ["ioc", "general"], ["query"], ["threat_context", "sources"], [_tool("investigate_ioc", "threat_intel.search", ["threat_context", "sources"], category="threat_intel")], aliases=["threat intel lookup"], natural_language_aliases=["threat intelligence search", "ti search"], risk_level="medium", risk_reasons=["external_network_or_submission"], approval_triggers=["external_submission", "unapproved_external_network"], policy_tags=["threat_intel", "external_lookup"], safety_tags=["read_only"], external_network=True),
        _capability("rule.generate", "Generate detection logic from grounded evidence.", ["detection"], ["evidence"], ["rule_logic", "detection_scope"], [], aliases=["generate rule"], safety_tags=["read_only"]),
        _capability("ir.approval.request", "Request analyst approval for containment or response actions.", ["incident_response"], ["action", "risk"], ["approval_status"], [], degraded_allowed=False, risk_level="high", risk_reasons=["ir_or_containment_action"], approval_required=True, approval_policy={"approval_required": True}, approval_triggers=["incident_response_action"], policy_tags=["approval", "incident_response"], safety_tags=["requires_human_approval"], read_only=False),
        _capability("ir.host.contain.propose", "Stage a non-destructive host containment proposal requiring evidence and approval.", ["incident_response"], ["target", "evidence_refs"], ["approval_status"], [], degraded_allowed=False, aliases=["contain host"], natural_language_aliases=["host containment", "isolate host"], risk_level="high", risk_reasons=["ir_or_containment_action"], approval_required=True, approval_policy={"approval_required": True}, approval_triggers=["containment", "host_isolation"], policy_tags=["incident_response", "containment"], safety_tags=["requires_human_approval"], read_only=False, destructive=True),
        _capability("ir.user.disable.propose", "Stage a non-destructive user disable proposal requiring evidence and approval.", ["incident_response"], ["target", "evidence_refs"], ["approval_status"], [], degraded_allowed=False, aliases=["disable user"], natural_language_aliases=["user disable", "lock account"], risk_level="high", risk_reasons=["ir_or_containment_action"], approval_required=True, approval_policy={"approval_required": True}, approval_triggers=["account_disable"], policy_tags=["incident_response", "containment"], safety_tags=["requires_human_approval"], read_only=False, destructive=True),
        _capability("ir.network.block.propose", "Stage a non-destructive network block proposal requiring evidence and approval.", ["incident_response"], ["target", "evidence_refs"], ["approval_status"], [], degraded_allowed=False, aliases=["block network"], natural_language_aliases=["network block", "block ip", "block domain"], risk_level="high", risk_reasons=["ir_or_containment_action"], approval_required=True, approval_policy={"approval_required": True}, approval_triggers=["network_block"], policy_tags=["incident_response", "containment"], safety_tags=["requires_human_approval"], read_only=False, destructive=True),
        _capability("clarification.request", "Ask a blocking clarification instead of executing an unsafe tool call.", ["general"], ["question"], ["clarification"], [], degraded_allowed=False, aliases=["ask clarification"], safety_tags=["read_only"]),
        _capability("case.context.read", "Read existing case context before answering or pivoting.", ["case", "general", "incident_response"], ["case_id_or_thread"], ["case_summary", "evidence_refs"], [], aliases=["read case context"], safety_tags=["read_only"]),
        _capability("config.capability.explain", "Explain available runtime capabilities and degraded integrations.", ["config"], ["question"], ["capability", "availability", "configuration"], [], aliases=["explain capabilities"], safety_tags=["read_only"]),
    ]
