"""Lane-to-facet coverage contracts for AISA investigations."""

from __future__ import annotations

from typing import Dict, List

from .coverage_model import CoverageRequirement

_LANE_FACETS: Dict[str, List[str]] = {
    "identity": ["user", "session", "source_ip", "host", "process", "timeline"],
    "log_identity": ["user", "session", "source_ip", "host", "process", "timeline"],
    "network_log": ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "backend", "raw_event"],
    "network_log_hunt": ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "certificate", "backend", "raw_event"],
    "host_process_log_hunt": ["timestamp", "host", "process", "command_line", "event_code", "user", "source_sourcetype", "backend", "raw_event"],
    "email": ["sender", "recipient", "delivery", "url_or_attachment", "host", "timeline"],
    "file": ["file_hash", "file_path", "process", "host", "network", "timeline"],
    "network": ["source_ip", "host", "network", "session", "timeline"],
    "process": ["process", "host", "user", "file_path", "network", "timeline"],
    "ioc": ["ioc", "network", "host", "timeline"],
}

_DESCRIPTIONS = {
    "user": "User or account principal is directly observed.",
    "session": "Session or logon identifier is directly observed.",
    "source_ip": "Source/client IP is directly observed.",
    "host": "Host, endpoint, or asset is directly observed.",
    "process": "Process or command execution is directly observed.",
    "network": "Network destination, URL, domain, or connection is directly observed.",
    "sender": "Email sender is directly observed.",
    "recipient": "Email recipient/mailbox is directly observed.",
    "delivery": "Email delivery or gateway/mailbox event is observed.",
    "url_or_attachment": "Email URL or attachment artifact is observed.",
    "file_hash": "File hash is directly observed.",
    "file_path": "File path/name is directly observed.",
    "ioc": "Indicator value and deterministic enrichment are observed.",
    "timeline": "At least one timestamped observation is available.",
    "timestamp": "Event timestamp is directly observed or the event is an explicitly pasted raw log artifact.",
    "destination_ip": "Destination IP is directly observed.",
    "destination_port": "Destination port is directly observed.",
    "protocol_app": "Protocol or application/service is directly observed.",
    "source_sourcetype": "Log source or sourcetype is directly observed.",
    "certificate": "Certificate/TLS metadata is directly observed when relevant.",
    "action": "Device or control action is directly observed.",
    "device": "Log device or telemetry source is directly observed.",
    "raw_event": "Raw event or stable raw-event reference is visible.",
    "backend": "Runtime log backend or inline artifact backend is explicit.",
    "command_line": "Process command line is directly observed.",
    "event_code": "Windows event code or detection event ID is directly observed.",
}


def requirements_for_lane(lane: str) -> List[CoverageRequirement]:
    normalized = str(lane or "ioc").strip().lower() or "ioc"
    facets = _LANE_FACETS.get(normalized, _LANE_FACETS["ioc"])
    return [
        CoverageRequirement(
            lane=normalized,
            facet=facet,
            description=_DESCRIPTIONS.get(facet, f"Coverage for {facet}."),
        )
        for facet in facets
    ]
