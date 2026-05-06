"""Deterministic parser and analyzer for pasted SOC network/security log artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_ALIAS_MAP = {
    "src": "source_ip", "srcip": "source_ip", "src_ip": "source_ip", "source_ip": "source_ip", "clientip": "source_ip", "client_ip": "source_ip",
    "dst": "destination_ip", "dest": "destination_ip", "dest_ip": "destination_ip", "dst_ip": "destination_ip", "dstip": "destination_ip", "destination_ip": "destination_ip", "remote_ip": "destination_ip",
    "dest_port": "destination_port", "dst_port": "destination_port", "dstport": "destination_port", "dpt": "destination_port", "port": "destination_port",
    "proto": "protocol_app", "protocol": "protocol_app", "transport": "protocol_app", "app": "protocol_app", "application": "protocol_app", "service": "protocol_app",
    "_time": "timestamp", "time": "timestamp", "@timestamp": "timestamp", "timestamp": "timestamp", "ts_utc": "timestamp", "utctime": "timestamp", "utc_time": "timestamp", "date": "timestamp",
    "action": "action", "act": "action", "event_action": "action",
    "host": "host", "hostname": "host", "device": "host", "devname": "host", "computer": "host", "computername": "host",
    "source": "source", "sourcetype": "sourcetype", "index": "index", "backend": "backend",
    "eventid": "event_id", "event_id": "event_id", "image": "process", "process": "process", "process_name": "process",
    "parentimage": "parent_process", "parent_process": "parent_process", "user": "user",
    "commandline": "command_line", "command_line": "command_line", "cmdline": "command_line",
    "hashes": "hashes", "hash": "hash", "sha256": "sha256", "sha1": "sha1", "md5": "md5", "sourceip": "source_ip",
    "ssl_subject_common_name": "certificate", "ssl_issuer_common_name": "certificate", "certificate": "certificate", "cert": "certificate",
}
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_KV_RE = re.compile(r"(?P<key>[A-Za-z_@][A-Za-z0-9_@.:-]*)=(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)")
_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


@dataclass
class ParsedLogEvent:
    event_id: str
    raw_event_ref: str
    raw_event_preview: str
    fields: Dict[str, Any] = field(default_factory=dict)
    source_format: str = "unknown"
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RawLogParseResult:
    schema_version: str = "raw-log-parse-result/v1"
    parser_id: str = "raw-log-parser/v1"
    raw_event_ref: str = ""
    artifact_type: str = "unknown_log"
    events: List[ParsedLogEvent] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)

    @property
    def best_fields(self) -> Dict[str, Any]:
        return dict(self.events[0].fields) if self.events else {}

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["events"] = [event.to_dict() for event in self.events]
        payload["parsed_fields"] = self.best_fields
        return payload


class RawLogParser:
    """Parse common pasted firewall, Splunk, Zeek/Suricata, syslog, and JSON events."""

    NETWORK_HINTS = ("sourcetype=", "source=", "src=", "src_ip=", "dst=", "dest_ip=", "dest_port=", "dpt=", "proto=", "protocol=", "action=", "stream:tcp", "fortigate", "suricata", "zeek", "firewall")

    def looks_like_raw_log(self, text: str) -> bool:
        lowered = str(text or "").lower()
        return bool(_KV_RE.search(lowered) and any(token in lowered for token in self.NETWORK_HINTS)) or self._looks_like_json_log(text) or bool(_TS_RE.search(text or "") and len(_IP_RE.findall(text or "")) >= 2)

    def parse(self, text: str) -> RawLogParseResult:
        raw = str(text or "").strip()
        raw_ref = _stable_id("artifact_raw", raw[:400])
        limitations: List[str] = []
        if not raw:
            return RawLogParseResult(raw_event_ref=raw_ref, limitations=["No raw log text was provided."])
        chunks = self._event_chunks(raw)
        events: List[ParsedLogEvent] = []
        for index, chunk in enumerate(chunks[:25]):
            fields, fmt = self._parse_event(chunk)
            fields.setdefault("raw_event_ref", f"{raw_ref}_{index:03d}")
            event_limits = self._limitations(fields)
            confidence = self._confidence(fields, fmt)
            events.append(ParsedLogEvent(
                event_id=_stable_id("logevt", raw_ref, index, chunk[:120]),
                raw_event_ref=fields["raw_event_ref"],
                raw_event_preview=chunk[:500],
                fields=fields,
                source_format=fmt,
                confidence=confidence,
                limitations=event_limits,
            ))
            limitations.extend(event_limits)
        artifact_type = self._artifact_type(events[0].fields if events else {}, raw)
        return RawLogParseResult(
            raw_event_ref=raw_ref,
            artifact_type=artifact_type,
            events=events,
            confidence=max([event.confidence for event in events], default=0.0),
            limitations=list(dict.fromkeys(limitations)),
        )

    def _event_chunks(self, raw: str) -> List[str]:
        stripped = raw.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return [stripped]
        return [line.strip() for line in raw.splitlines() if line.strip()] or [stripped]

    def _parse_event(self, chunk: str) -> tuple[Dict[str, Any], str]:
        data = self._parse_json(chunk)
        fmt = "json" if isinstance(data, dict) else "key_value" if _KV_RE.search(chunk) else "syslog_text"
        raw_fields = data if isinstance(data, dict) else self._parse_kv(chunk)
        fields: Dict[str, Any] = {}
        for key, value in raw_fields.items():
            normalized = _ALIAS_MAP.get(str(key).strip().lower(), str(key).strip().lower())
            if value in (None, "", [], {}):
                continue
            if normalized == "source" and str(value).lower().startswith("stream:"):
                fields["source"] = value
                fields.setdefault("sourcetype", value)
            else:
                fields[normalized] = str(value).strip().strip('"\'') if not isinstance(value, (dict, list)) else value
        for preferred_ts_key in ("ts_utc", "utctime", "utc_time"):
            if raw_fields.get(preferred_ts_key):
                fields["timestamp"] = str(raw_fields[preferred_ts_key]).strip().strip('"\'')
                break
        if not fields.get("timestamp"):
            ts = _TS_RE.search(chunk)
            if ts:
                fields["timestamp"] = ts.group(0)
        ips = _IP_RE.findall(chunk)
        if ips and not fields.get("source_ip"):
            fields["source_ip"] = ips[0]
        if len(ips) > 1 and not fields.get("destination_ip"):
            fields["destination_ip"] = ips[1]
        if fields.get("hashes"):
            self._normalize_hashes(fields)
        if fields.get("process") and not fields.get("file_path") and "\\" in str(fields.get("process")):
            fields["file_path"] = fields["process"]
        if fields.get("protocol_app") and fields.get("certificate"):
            fields["protocol_app"] = f"{fields['protocol_app']}_ssl" if "ssl" not in str(fields["protocol_app"]).lower() else fields["protocol_app"]
        if not fields.get("backend"):
            lowered = chunk.lower()
            fields["backend"] = "splunk" if "sourcetype=" in lowered or "source=" in lowered else "inline_artifact"
        return fields, fmt

    def _normalize_hashes(self, fields: Dict[str, Any]) -> None:
        for part in re.split(r"[,;\s]+", str(fields.get("hashes") or "")):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip().lower()
            value = value.strip()
            if name in {"md5", "sha1", "sha256"} and value:
                fields.setdefault(name, value)
        if fields.get("sha256"):
            fields.setdefault("hash", fields["sha256"])
        elif fields.get("sha1"):
            fields.setdefault("hash", fields["sha1"])
        elif fields.get("md5"):
            fields.setdefault("hash", fields["md5"])

    def _parse_json(self, chunk: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(chunk)
        except Exception:
            return None
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0]
        return data if isinstance(data, dict) else None

    def _parse_kv(self, chunk: str) -> Dict[str, Any]:
        return {m.group("key"): m.group("value").strip().strip('"\'') for m in _KV_RE.finditer(chunk)}

    def _looks_like_json_log(self, text: str) -> bool:
        data = self._parse_json(str(text or "").strip())
        if not isinstance(data, dict):
            return False
        keys = {str(k).lower() for k in data.keys()}
        return bool(keys & set(_ALIAS_MAP.keys())) and bool(keys & {"src", "src_ip", "dest_ip", "dst", "source_ip", "destination_ip", "sourcetype"})

    def _limitations(self, fields: Dict[str, Any]) -> List[str]:
        limits = []
        for key, label in (("timestamp", "No event timestamp was parsed."), ("action", "No allow/deny/action outcome was provided.")):
            if not fields.get(key):
                limits.append(label)
        if not fields.get("source_ip") or not fields.get("destination_ip"):
            limits.append("Source or destination IP context is incomplete.")
        limits.append("Single pasted log artifacts cannot prove malicious, benign, compromised, or safe status without corroborating evidence.")
        return list(dict.fromkeys(limits))

    def _confidence(self, fields: Dict[str, Any], fmt: str) -> float:
        core = ["source_ip", "destination_ip", "destination_port", "protocol_app", "host", "source", "sourcetype", "backend", "raw_event_ref"]
        covered = sum(1 for key in core if fields.get(key))
        base = 0.45 if fmt == "syslog_text" else 0.62
        return min(0.95, base + covered * 0.045)

    def _artifact_type(self, fields: Dict[str, Any], raw: str) -> str:
        lowered = raw.lower()
        if "sysmon" in lowered or fields.get("event_id") or fields.get("process") or fields.get("parent_process"):
            return "sysmon_log_event"
        if "stream:tcp" in lowered:
            return "splunk_stream_tcp"
        if "fortigate" in lowered or "devname=" in lowered:
            return "firewall_log"
        if fields.get("sourcetype") or fields.get("source"):
            return "splunk_log_event"
        return "network_security_log"


def analyze_log_artifact(raw_log_text: str = "", compiled_input_ref: str = "", **kwargs: Any) -> Dict[str, Any]:
    """Return deterministic, non-verdict-bearing analysis for pasted raw log artifacts."""
    parser = RawLogParser()
    parse = parser.parse(raw_log_text or kwargs.get("raw_event") or kwargs.get("text") or "")
    fields = parse.best_fields
    obs_id = _stable_id("obs_log", parse.raw_event_ref, fields)
    facets = [facet for facet, keys in {
        "timestamp": ["timestamp"], "source_ip": ["source_ip"], "destination_ip": ["destination_ip"], "destination_port": ["destination_port"],
        "protocol_app": ["protocol_app"], "action": ["action"], "host": ["host"], "process": ["process"], "parent_process": ["parent_process"],
        "user": ["user"], "command_line": ["command_line"], "hash": ["hash", "sha256", "sha1", "md5"], "source_sourcetype": ["source", "sourcetype"],
        "backend": ["backend"], "certificate": ["certificate"], "raw_event": ["raw_event_ref"],
    }.items() if any(fields.get(k) for k in keys)]
    missing = [facet for facet in ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "action", "host", "source_sourcetype", "backend", "raw_event"] if facet not in facets]
    structured_verdict = {
        "schema_version": "structured-verdict/v1",
        "verdict": "inconclusive",
        "scope": "pasted_log_artifact",
        "allowed_final": True,
        "summary": "Pasted network/security log artifact parsed; no malicious or benign conclusion is supported from this evidence alone.",
        "supported_claims": [{"claim": f"Parsed log fields: {', '.join(sorted(fields.keys()))}.", "evidence_refs": [obs_id]}] if fields else [],
        "unsupported_claims": [{"claim": "The event is malicious, benign, compromised, exploited, clean, or safe.", "reason": "Deterministic evidence is limited to pasted log fields without recurrence, baseline, endpoint, action outcome, or enrichment evidence."}],
        "limitations": parse.limitations,
        "coverage": {"lane": "network_log_hunt", "status": "partial", "covered_facets": facets, "missing_facets": missing},
        "ui_badge": "inconclusive",
        "authority": "deterministic_evidence_gate",
    }
    return {
        "schema_version": "log-artifact-analysis-result/v1",
        "analysis_id": _stable_id("logart", parse.raw_event_ref, compiled_input_ref),
        "compiled_input_ref": compiled_input_ref,
        "artifact_type": parse.artifact_type,
        "backend": fields.get("backend", "inline_artifact"),
        "source": fields.get("source"),
        "sourcetype": fields.get("sourcetype"),
        "raw_event_ref": parse.raw_event_ref,
        "parsed_fields": fields,
        "parser": parse.to_dict(),
        "observations": [{"observation_id": obs_id, "quality": "typed_observation", "facets": facets, "canonical_facts": fields, "typed_fact": {"type": "log_event", "quality": parse.confidence}, "tool_name": "analyze_log_artifact"}],
        "coverage": structured_verdict["coverage"],
        "hypotheses": [{"statement": "Event may represent normal service traffic or suspicious activity depending on environment baseline and surrounding events.", "status": "candidate", "support_refs": [obs_id]}],
        "limitations": parse.limitations,
        "structured_verdict": structured_verdict,
        "verdict": "INCONCLUSIVE",
        "authority": "deterministic_parser_non_verdict",
    }
