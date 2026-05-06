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
    schema_version: str = "capability-descriptor/v1"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["compatible_tools"] = [item.to_dict() for item in self.compatible_tools]
        return payload


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

    def capabilities_for(self, objective: Any) -> List[CapabilityContract]:
        capability_ids = list(getattr(objective, "capabilities_required", []) or [])
        if not capability_ids and isinstance(objective, dict):
            capability_ids = list(objective.get("capabilities_required") or [])
        return [self._capabilities[item] for item in capability_ids if item in self._capabilities]

    def all(self) -> List[CapabilityContract]:
        return list(self._capabilities.values())


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


def default_capability_contracts() -> List[CapabilityContract]:
    return [
        CapabilityContract(
            capability_id="log.search",
            description="Search security logs, SIEM data, or firewall telemetry for evidence.",
            domains=["network_log_hunt", "log_security", "incident_response"],
            required_inputs=["query_or_entities", "timerange"],
            output_facets=["timestamp", "source_ip", "destination_ip", "action", "device", "raw_event", "backend", "source", "destination", "events"],
            compatible_tools=[_tool("search_logs", "log.search", ["timestamp", "source_ip", "destination_ip", "action", "raw_event", "backend", "events", "coverage", "timerange"], supports_timerange=True)],
            optional_inputs=["backend", "index", "sourcetype", "limit"],
            evidence_role="primary_observation",
        ),
        CapabilityContract(
            capability_id="log.analyze.inline",
            description="Analyze a pasted raw log event as local inline evidence without requiring live SIEM access.",
            domains=["network_log_hunt", "log_security"],
            required_inputs=["raw_log_event"],
            output_facets=["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "certificate", "backend", "raw_event"],
            compatible_tools=[_tool("analyze_log_artifact", "log.analyze.inline", ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "backend", "raw_event"])],
            optional_inputs=["backend", "source", "sourcetype"],
            evidence_role="primary_observation",
        ),
        CapabilityContract(
            capability_id="ioc.enrich",
            description="Enrich an observable with deterministic threat intelligence.",
            domains=["ioc", "log_security", "email", "file"],
            required_inputs=["observable"],
            output_facets=["reputation", "ownership", "sightings"],
            compatible_tools=[_tool("investigate_ioc", "ioc.enrich", ["reputation", "verdict", "sources"], category="threat_intel")],
        ),
        CapabilityContract(
            capability_id="email.parse.inline",
            description="Parse inline email text supplied in chat without pretending it is a local file.",
            domains=["email"],
            required_inputs=["raw_email_text_or_sender_url"],
            output_facets=["sender", "recipient", "subject", "urls", "headers", "body"],
            compatible_tools=[],
        ),
        CapabilityContract(
            capability_id="email.analyze",
            description="Analyze email artifacts, headers, sender auth, URLs, and attachments.",
            domains=["email"],
            required_inputs=["email_artifact_or_text"],
            output_facets=["headers", "sender", "auth_results", "urls", "attachments"],
            compatible_tools=[_tool("analyze_email", "email.analyze", ["headers", "urls", "attachments", "verdict"])],
        ),
        CapabilityContract(
            capability_id="file.analyze.static",
            description="Perform static file or malware artifact analysis.",
            domains=["file"],
            required_inputs=["file_or_hash"],
            output_facets=["file_identity", "hashes", "strings", "static_indicators"],
            compatible_tools=[_tool("analyze_malware", "file.analyze.static", ["file_metadata", "indicators", "verdict"])],
        ),
        CapabilityContract(
            capability_id="file.analyze.sandbox",
            description="Analyze file behavior through sandbox-backed evidence when available.",
            domains=["file"],
            required_inputs=["file_or_hash"],
            output_facets=["behavior", "network", "process", "persistence"],
            compatible_tools=[_tool("analyze_malware", "file.analyze.sandbox", ["behavior", "network", "process"], category="sandbox")],
        ),
        CapabilityContract(
            capability_id="ioc.extract",
            description="Extract observables from analyst text or artifacts.",
            domains=["general", "email", "file", "ioc"],
            required_inputs=["text_or_artifact"],
            output_facets=["observables", "observable_types"],
            compatible_tools=[_tool("extract_iocs", "ioc.extract", ["observables", "observable_types"])],
        ),
        CapabilityContract("case.summarize", "Summarize prior task or case evidence without starting extraction.", ["case", "case_follow_up"], ["task_ref"], ["case_summary", "evidence_refs"], []),
        CapabilityContract("correlate.findings", "Correlate findings across observations.", ["general", "log_security", "email", "file", "ioc"], ["observations"], ["linked_entities", "timeline"], [_tool("correlate_findings", "correlate.findings", ["linked_entities", "timeline"])]),
        CapabilityContract("findings.correlate", "Correlate findings across observations.", ["general", "log_security", "email", "file", "ioc"], ["observations"], ["linked_entities", "timeline"], []),
        CapabilityContract("threat_intel.search", "Search threat-intelligence context for a topic or observable.", ["ioc", "general"], ["query"], ["threat_context", "sources"], [_tool("investigate_ioc", "threat_intel.search", ["threat_context", "sources"], category="threat_intel")]),
        CapabilityContract("rule.generate", "Generate detection logic from grounded evidence.", ["detection"], ["evidence"], ["rule_logic", "detection_scope"], []),
        CapabilityContract("ir.approval.request", "Request analyst approval for containment or response actions.", ["incident_response"], ["action", "risk"], ["approval_status"], [], degraded_allowed=False),
        CapabilityContract("ir.host.contain.propose", "Stage a non-destructive host containment proposal requiring evidence and approval.", ["incident_response"], ["target", "evidence_refs"], ["approval_status"], [], degraded_allowed=False),
        CapabilityContract("ir.user.disable.propose", "Stage a non-destructive user disable proposal requiring evidence and approval.", ["incident_response"], ["target", "evidence_refs"], ["approval_status"], [], degraded_allowed=False),
        CapabilityContract("ir.network.block.propose", "Stage a non-destructive network block proposal requiring evidence and approval.", ["incident_response"], ["target", "evidence_refs"], ["approval_status"], [], degraded_allowed=False),
        CapabilityContract("clarification.request", "Ask a blocking clarification instead of executing an unsafe tool call.", ["general"], ["question"], ["clarification"], [], degraded_allowed=False),
        CapabilityContract("case.context.read", "Read existing case context before answering or pivoting.", ["case", "general", "incident_response"], ["case_id_or_thread"], ["case_summary", "evidence_refs"], []),
        CapabilityContract("config.capability.explain", "Explain available runtime capabilities and degraded integrations.", ["config"], ["question"], ["capability", "availability", "configuration"], []),
    ]
