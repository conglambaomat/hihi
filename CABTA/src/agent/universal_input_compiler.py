"""Universal input compiler for AISA Vibe SOC chat/artifact inputs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from .raw_log_parser import RawLogParser
from .soc_task_state import SOCTaskState

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_event_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace(" ", "T", 1)
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _artifact_timerange_from_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = None
    if isinstance(fields, dict):
        for key in ("ts_utc", "timestamp", "_time", "@timestamp", "utcTime", "UtcTime", "event_time", "time"):
            timestamp = _parse_event_timestamp(fields.get(key))
            if timestamp:
                break
    if not timestamp:
        return {"source": "default", "effective": "24h", "normalization_reason": "no_artifact_timestamp_default_timerange"}
    earliest = timestamp - timedelta(minutes=30)
    latest = timestamp + timedelta(hours=2)
    def fmt(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "source": "artifact_timestamp",
        "requested": fmt(timestamp),
        "effective": f"{fmt(earliest)}..{fmt(latest)}",
        "event_timestamp": fmt(timestamp),
        "earliest": fmt(earliest),
        "latest": fmt(latest),
        "normalization_reason": "pasted_artifact_event_timestamp_window",
    }


@dataclass
class CompiledInput:
    schema_version: str = "compiled-input/v1"
    compiled_input_id: str = ""
    raw_input_ref: str = "chat_message"
    input_kind: str = "natural_request"
    artifact_type: str = "unknown"
    lane: str = "generic"
    objective_hint: str = ""
    entities: List[Dict[str, Any]] = field(default_factory=list)
    requested_backends: List[str] = field(default_factory=list)
    requested_timerange: Dict[str, Any] = field(default_factory=dict)
    safety_flags: List[str] = field(default_factory=list)
    evidence_scope: Dict[str, Any] = field(default_factory=dict)
    parser: Dict[str, Any] = field(default_factory=dict)
    artifact_ref: str = ""
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    artifact_candidates: List[Dict[str, Any]] = field(default_factory=list)
    clarifications: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        if not self.compiled_input_id:
            self.compiled_input_id = _stable_id("ci", self.raw_input_ref, self.input_kind, self.objective_hint, self.created_at)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UniversalInputCompiler:
    """Compile natural/raw SOC input into objective, evidence, and capability contracts."""

    def __init__(self, raw_log_parser: RawLogParser | None = None) -> None:
        self.raw_log_parser = raw_log_parser or RawLogParser()

    def compile(self, raw_input: str, context: Dict[str, Any] | None = None) -> CompiledInput:
        context = dict(context or {})
        text = str(raw_input or "").strip()
        raw_ref = _stable_id("chatmsg", text[:500], context.get("session_id"), context.get("thread_id"))
        requested_backends = self._requested_backends(text, context)
        timerange = self._requested_timerange(text, context)
        entities = self._entities(text)
        evidence_scope = {"allowed_sources": ["chat_message"], "disallowed_claims": ["confirmed_compromise", "malicious_verdict_without_scoring", "benign_verdict_without_scoring"], "scope": "chat_input"}
        structured = self._compile_structured_json(text, raw_ref, entities, requested_backends, timerange, evidence_scope)
        if structured:
            return structured
        alert = self._compile_soc_alert_text(text, raw_ref, entities, requested_backends, timerange, evidence_scope)
        if alert:
            return alert
        if self.raw_log_parser.looks_like_raw_log(text):
            parse = self.raw_log_parser.parse(text)
            fields = parse.best_fields
            artifact_ref = parse.raw_event_ref
            for role, key in (("source_ip", "source_ip"), ("destination_ip", "destination_ip")):
                if fields.get(key):
                    entities.append({"type": "ip", "value": fields[key], "role": role, "source": "raw_log_parser", "confidence": parse.confidence})
            if fields.get("host"):
                entities.append({"type": "host", "value": fields["host"], "role": "host", "source": "raw_log_parser", "confidence": parse.confidence})
            if fields.get("backend") and fields["backend"] not in requested_backends:
                requested_backends.append(str(fields["backend"]))
            artifact_timerange = timerange or _artifact_timerange_from_fields(fields)
            return CompiledInput(
                raw_input_ref=raw_ref,
                input_kind="raw_log_artifact",
                artifact_type=parse.artifact_type,
                lane="network_log_hunt",
                objective_hint="Analyze pasted network/security log artifact in network-log scope.",
                entities=self._dedupe_entities(entities),
                requested_backends=requested_backends,
                requested_timerange=artifact_timerange,
                evidence_scope={**evidence_scope, "allowed_sources": ["pasted_artifact"], "scope": "pasted_log_artifact"},
                parser={"parser_id": parse.parser_id, "confidence": parse.confidence, "limitations": parse.limitations, "raw_event_ref": parse.raw_event_ref, "parsed_fields": fields},
                artifact_ref=artifact_ref,
            )
        artifact = self._compile_email_or_ioc_artifact(text, raw_ref, entities, requested_backends, timerange, evidence_scope)
        if artifact:
            return artifact
        lane = "network_log_hunt" if self._looks_like_log_search(text) else "ioc" if entities else "generic"
        clarifications = []
        limitations = []
        if lane == "generic" and len(text.split()) <= 8:
            clarifications.append({"question": "What SOC artifact or observable should AISA investigate?", "reason": "Input has no normalized IOC, log, email, alert, or clear investigation objective."})
            limitations.append("insufficient_typed_soc_artifact")
        return CompiledInput(
            raw_input_ref=raw_ref,
            input_kind="natural_request" if lane != "ioc" else "ioc",
            artifact_type="observable" if lane == "ioc" else "unknown",
            lane=lane,
            objective_hint=text[:240] or "AISA SOC request",
            entities=self._dedupe_entities(entities),
            requested_backends=requested_backends,
            requested_timerange=timerange,
            evidence_scope=evidence_scope,
            parser={"parser_id": "universal-input-compiler/v1", "confidence": 0.62 if lane != "generic" else 0.35, "limitations": limitations},
            artifacts=[],
            artifact_candidates=[],
            clarifications=clarifications,
            limitations=limitations,
        )

    def apply_to_task_state(self, task: SOCTaskState, compiled: CompiledInput) -> SOCTaskState:
        payload = compiled.to_dict()
        task.compiled_input = payload
        task.lane = compiled.lane
        task.entities = self._dedupe_entities([*list(task.entities or []), *compiled.entities])
        task.requested_backends = list(dict.fromkeys([*list(task.requested_backends or []), *compiled.requested_backends]))
        if compiled.requested_timerange:
            task.timerange = {**dict(task.timerange or {}), **compiled.requested_timerange}
        if compiled.input_kind == "raw_log_artifact":
            fields = dict((compiled.parser or {}).get("parsed_fields") or {})
            task.artifacts = [item for item in list(task.artifacts or []) if item.get("type") not in {"inline_email"}]
            task.add_artifact(
                "inline_log_event",
                source="pasted_artifact",
                confidence=float((compiled.parser or {}).get("confidence") or 0.0),
                artifact_id=compiled.artifact_ref,
                raw_event_ref=compiled.artifact_ref,
                fields=fields,
                backend=fields.get("backend"),
                source_name=fields.get("source"),
                sourcetype=fields.get("sourcetype"),
            )
            task.required_capabilities = ["log.analyze.inline"]
        elif compiled.artifacts:
            for artifact in compiled.artifacts:
                if isinstance(artifact, dict) and not any(existing.get("artifact_id") == artifact.get("artifact_id") for existing in task.artifacts):
                    task.artifacts.append(dict(artifact))
            if not task.required_capabilities:
                if compiled.input_kind == "email_artifact":
                    task.required_capabilities = ["email.parse.inline"]
                elif compiled.input_kind in {"json_artifact", "soc_alert_text"}:
                    task.required_capabilities = ["log.search"] if compiled.lane == "network_log_hunt" else ["ioc.extract"]
                elif compiled.lane == "ioc":
                    task.required_capabilities = ["ioc.enrich"]
        elif not task.required_capabilities:
            task.required_capabilities = ["log.search"] if compiled.lane == "network_log_hunt" else ["ioc.enrich"] if compiled.lane == "ioc" else ["config.capability.explain"]
        task.objective_contract = self.build_objective_contract(task, compiled)
        task.field_sources.setdefault("compiler", {"compiler_id": "universal-input-compiler/v1", "compiled_input_id": compiled.compiled_input_id, "confidence": (compiled.parser or {}).get("confidence"), "limitations": (compiled.parser or {}).get("limitations", [])})
        task.add_progress("input_compiled", compiled_input_id=compiled.compiled_input_id, input_kind=compiled.input_kind, lane=compiled.lane, artifact_type=compiled.artifact_type)
        return task

    def build_objective_contract(self, task: SOCTaskState, compiled: CompiledInput) -> Dict[str, Any]:
        existing = dict(task.objective_contract or {})
        contract_id = existing.get("contract_id") or _stable_id("obj", task.task_id, compiled.compiled_input_id)
        return {
            **existing,
            "schema_version": "objective-contract/v2",
            "contract_id": contract_id,
            "summary": compiled.objective_hint or task.analyst_objective,
            "analyst_objective": task.analyst_objective,
            "objective_type": task.intent or "investigation",
            "lane": compiled.lane,
            "coverage_lane": compiled.lane,
            "compiled_input_ref": compiled.compiled_input_id,
            "compiled_input": compiled.to_dict(),
            "artifact_scope": {"artifact_type": compiled.artifact_type, "input_kind": compiled.input_kind, "artifact_ref": compiled.artifact_ref},
            "evidence_scope": compiled.evidence_scope,
            "forbidden_claims": list(compiled.evidence_scope.get("disallowed_claims") or []),
            "entities": compiled.entities,
            "requested_backends": compiled.requested_backends,
            "timerange": compiled.requested_timerange,
            "effective_timerange": compiled.requested_timerange.get("effective") if isinstance(compiled.requested_timerange, dict) else None,
            "capabilities_required": list(task.required_capabilities or []),
            "final_answer_contract": {"requires_final_answer_gate": compiled.input_kind not in {"help", "general"}, "structured_verdict_only": True},
        }

    def _requested_backends(self, text: str, context: Dict[str, Any]) -> List[str]:
        found = []
        lowered = text.lower()
        for backend in ("splunk", "sentinel", "kql", "fortigate", "fortinet", "zeek", "suricata"):
            if backend in lowered:
                found.append("splunk" if backend == "splunk" else backend)
        for backend in context.get("requested_backends") or []:
            if str(backend).strip():
                found.append(str(backend).strip().lower())
        return list(dict.fromkeys(found))

    def _requested_timerange(self, text: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if context.get("effective_timerange"):
            return {"source": "context", "effective": context.get("effective_timerange")}
        match = re.search(r"\b(last\s+\d+\s*(?:minutes?|hours?|days?)|\d+\s*[hdm]|24h|7d|30d)\b", text, re.IGNORECASE)
        if match:
            return {"source": "user", "requested": match.group(1), "effective": match.group(1)}
        return {}

    def _compile_structured_json(self, text: str, raw_ref: str, entities: List[Dict[str, Any]], requested_backends: List[str], timerange: Dict[str, Any], evidence_scope: Dict[str, Any]) -> CompiledInput | None:
        try:
            parsed = json.loads(text)
        except Exception:
            return None
        events = parsed if isinstance(parsed, list) else [parsed] if isinstance(parsed, dict) else []
        if not events:
            return None
        first = events[0] if isinstance(events[0], dict) else {}
        keys = {str(k).lower() for event in events if isinstance(event, dict) for k in event.keys()}
        is_alert = bool({"alert", "rule", "signature", "severity", "event_type", "eventid", "src_ip", "dest_ip"} & keys)
        artifact_type = "alert_json" if is_alert else "log_json_array" if isinstance(parsed, list) else "json_event"
        lane = "alert_triage" if is_alert else "network_log_hunt"
        for event in events:
            if not isinstance(event, dict):
                continue
            for key, role in (("src_ip", "source_ip"), ("source_ip", "source_ip"), ("dest_ip", "destination_ip"), ("destination_ip", "destination_ip"), ("host", "host"), ("user", "user"), ("url", "url")):
                if event.get(key):
                    etype = "ip" if "ip" in key else key
                    entities.append({"type": etype, "value": str(event.get(key)), "role": role, "source": "json_parser", "confidence": 0.84})
        artifact_id = _stable_id("artifact", raw_ref, artifact_type, text[:200])
        artifact_timerange = timerange or _artifact_timerange_from_fields(first)
        return CompiledInput(raw_input_ref=raw_ref, input_kind="json_artifact", artifact_type=artifact_type, lane=lane, objective_hint=f"Analyze pasted {artifact_type.replace('_', ' ')} artifact.", entities=self._dedupe_entities(entities), requested_backends=requested_backends, requested_timerange=artifact_timerange, evidence_scope={**evidence_scope, "allowed_sources": ["pasted_artifact"], "scope": "pasted_json_artifact"}, parser={"parser_id": "json-artifact-compiler/v1", "confidence": 0.82, "limitations": [], "parsed_fields": first, "event_count": len(events)}, artifact_ref=artifact_id, artifacts=[{"artifact_id": artifact_id, "type": artifact_type, "source": "pasted_artifact", "confidence": 0.82, "event_count": len(events), "parsed_fields": first}])

    def _compile_soc_alert_text(self, text: str, raw_ref: str, entities: List[Dict[str, Any]], requested_backends: List[str], timerange: Dict[str, Any], evidence_scope: Dict[str, Any]) -> CompiledInput | None:
        lowered = text.lower()
        markers = ("alert type", "alert time", "alert details", "rule name", "severity", "investigation start time")
        if "alert" not in lowered or sum(1 for marker in markers if marker in lowered) < 2:
            return None
        labels = "Event ID|Rule Name|Alert Type|Severity|Alert Time|Investigation Start Time|Analyst|Alert Details"
        fields: Dict[str, Any] = {}
        for label in labels.split("|"):
            match = re.search(rf"\b{label}\s*:?\s+(.*?)(?=\s+\b(?:{labels})\b\s*:?|$)", text, re.IGNORECASE)
            if match:
                fields[label.lower().replace(" ", "_")] = match.group(1).strip().rstrip(".")
        cmd = re.search(r"\b(Get-WmiObject\s+-Class\s+[A-Za-z0-9_]+)\b", text, re.IGNORECASE)
        if cmd:
            fields["command_line"] = cmd.group(1)
        host = re.search(r"\bon\s+([A-Z0-9][A-Z0-9_.-]*-[A-Z0-9_.-]+)\b", text, re.IGNORECASE)
        if host:
            fields["host"] = host.group(1).rstrip(".")
        for key, etype, role in (("host", "host", "asset"), ("rule_name", "rule", "detection_rule"), ("event_id", "event_id", "event_code"), ("command_line", "command_line", "process_command")):
            if fields.get(key):
                entities.append({"type": etype, "value": str(fields[key]), "role": role, "source": "alert_text_parser", "confidence": 0.88})
        if "wmi" in lowered:
            entities.append({"type": "technique", "value": "System Information Discovery via WMI", "role": "attack_technique", "source": "alert_text_parser", "confidence": 0.84})
        alert_time = str(fields.get("alert_time") or "").strip()
        alert_timerange = timerange or ({"source": "alert_time", "requested": alert_time, "value": alert_time, "effective": alert_time, "window_hint": "-30m..+2h", "normalization_reason": "alert_time_preserved_for_query_window"} if alert_time else {})
        artifact_id = _stable_id("artifact", raw_ref, "soc_alert_text", text[:200])
        lane = "host_process_log_hunt" if fields.get("command_line") or "wmi" in lowered else "network_log_hunt"
        return CompiledInput(raw_input_ref=raw_ref, input_kind="soc_alert_text", artifact_type="soc_alert", lane=lane, objective_hint="Investigate pasted SOC alert through log search and correlation; alert category is not a file artifact.", entities=self._dedupe_entities(entities), requested_backends=requested_backends, requested_timerange=alert_timerange, evidence_scope={**evidence_scope, "allowed_sources": ["chat_message", "log_search", "correlation"], "scope": "soc_alert_investigation"}, parser={"parser_id": "soc-alert-text-compiler/v1", "confidence": 0.86, "limitations": ["alert_type_is_category_not_file_artifact"], "parsed_fields": fields}, artifact_ref=artifact_id, artifacts=[{"artifact_id": artifact_id, "type": "soc_alert", "source": "chat_message", "confidence": 0.86, "parsed_fields": fields}])

    def _compile_email_or_ioc_artifact(self, text: str, raw_ref: str, entities: List[Dict[str, Any]], requested_backends: List[str], timerange: Dict[str, Any], evidence_scope: Dict[str, Any]) -> CompiledInput | None:
        lowered = text.lower()
        urls = _URL_RE.findall(text)
        hashes = _HASH_RE.findall(text)
        emails = _EMAIL_RE.findall(text)
        looks_email = any(token in lowered for token in ("from:", "to:", "subject:", "received:", "return-path:", "dkim-signature", "message-id:")) or (emails and "subject" in lowered)
        if looks_email:
            artifact_id = _stable_id("artifact", raw_ref, "inline_email", text[:200])
            for url in urls:
                entities.append({"type": "url", "value": url, "role": "embedded_url", "source": "email_parser", "confidence": 0.86})
            for email in emails:
                entities.append({"type": "email", "value": email.lower(), "role": "mailbox", "source": "email_parser", "confidence": 0.82})
            return CompiledInput(raw_input_ref=raw_ref, input_kind="email_artifact", artifact_type="inline_email", lane="phishing_investigation", objective_hint="Analyze pasted email headers/body for phishing and authentication limitations.", entities=self._dedupe_entities(entities), requested_backends=requested_backends, requested_timerange=timerange, evidence_scope={**evidence_scope, "allowed_sources": ["pasted_artifact"], "scope": "pasted_email_artifact"}, parser={"parser_id": "email-artifact-compiler/v1", "confidence": 0.8, "limitations": ["email_headers_may_be_partial"]}, artifact_ref=artifact_id, artifacts=[{"artifact_id": artifact_id, "type": "inline_email", "source": "pasted_artifact", "confidence": 0.8, "urls": urls, "mailboxes": emails, "raw_text": text}])
        if urls or hashes or len(entities) > 1:
            for url in urls:
                entities.append({"type": "url", "value": url, "role": "observable", "source": "compiler", "confidence": 0.84})
            for hash_value in hashes:
                entities.append({"type": "hash", "value": hash_value.lower(), "role": "observable", "source": "compiler", "confidence": 0.86})
            artifact_type = "ioc_bundle" if len(urls) + len(hashes) + len(entities) > 1 else "observable"
            artifact_id = _stable_id("artifact", raw_ref, artifact_type, text[:200])
            return CompiledInput(raw_input_ref=raw_ref, input_kind="ioc_bundle" if artifact_type == "ioc_bundle" else "ioc", artifact_type=artifact_type, lane="ioc", objective_hint="Enrich and triage normalized observables without accepting user-supplied verdict instructions.", entities=self._dedupe_entities(entities), requested_backends=requested_backends, requested_timerange=timerange, evidence_scope=evidence_scope, parser={"parser_id": "ioc-bundle-compiler/v1", "confidence": 0.82, "limitations": ["parsing_does_not_assign_verdict"]}, artifact_ref=artifact_id, artifacts=[{"artifact_id": artifact_id, "type": artifact_type, "source": "message", "confidence": 0.82}])
        return None

    def _entities(self, text: str) -> List[Dict[str, Any]]:
        entities = [{"type": "ip", "value": ip, "role": "observable", "source": "compiler", "confidence": 0.78} for ip in _IP_RE.findall(text)]
        for url in _URL_RE.findall(text):
            entities.append({"type": "url", "value": url, "role": "observable", "source": "compiler", "confidence": 0.84})
        for hash_value in _HASH_RE.findall(text):
            entities.append({"type": "hash", "value": hash_value.lower(), "role": "observable", "source": "compiler", "confidence": 0.86})
        for email in _EMAIL_RE.findall(text):
            entities.append({"type": "email", "value": email.lower(), "role": "observable", "source": "compiler", "confidence": 0.76})
        for domain in _DOMAIN_RE.findall(text):
            if not _IP_RE.fullmatch(domain) and "@" not in domain:
                entities.append({"type": "domain", "value": domain.lower(), "role": "observable", "source": "compiler", "confidence": 0.72})
        return self._dedupe_entities(entities)

    def _looks_like_log_search(self, text: str) -> bool:
        lowered = text.lower()
        return any(token in lowered for token in ("log", "splunk", "hunt", "siem", "sourcetype", "firewall", "network event"))

    def _dedupe_entities(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in entities:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("type")), str(item.get("value")), str(item.get("role")))
            if key in seen or not item.get("value"):
                continue
            seen.add(key)
            deduped.append(item)
        return deduped
