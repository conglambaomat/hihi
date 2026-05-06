"""Typed parameter binding for AISA SOC capability actions."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .capability_actions import CapabilityAction


@dataclass
class ParameterBindingResult:
    action_id: str
    params: Dict[str, Any] = field(default_factory=dict)
    missing_required: List[str] = field(default_factory=list)
    invalid_fields: List[str] = field(default_factory=list)
    field_sources: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    needs_clarification: bool = False
    clarification_questions: List[str] = field(default_factory=list)
    schema_version: str = "parameter-binding-result/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ParameterBinder:
    """Bind canonical task state into typed capability params with leakage guards."""

    _WIN_PATH_RE = re.compile(r"([A-Za-z]:[\\/](?:[^\r\n,;]+?))(?:\s+(?:and|but|then|please|tell|not uploaded|was not uploaded)\b|$)", re.IGNORECASE)
    _URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)

    def bind(self, action: CapabilityAction | Dict[str, Any], task_state: Any, objective_contract: Optional[Dict[str, Any]] = None, context: Optional[Dict[str, Any]] = None) -> ParameterBindingResult:
        action_obj = action if isinstance(action, CapabilityAction) else CapabilityAction.from_dict(action)
        objective_contract = objective_contract if isinstance(objective_contract, dict) else getattr(task_state, "objective_contract", {}) or {}
        context = dict(context or {})
        capability = action_obj.capability_id
        raw = str(getattr(task_state, "raw_request", "") or objective_contract.get("analyst_objective") or "")
        params: Dict[str, Any] = dict(action_obj.bound_params or {})
        sources: Dict[str, Any] = {}
        missing: List[str] = []
        questions: List[str] = []

        if capability == "log.search":
            params.update(self._bind_log_search(raw, task_state, objective_contract))
            sources.update({key: "task_state_or_message" for key in params})
        elif capability == "log.analyze.inline":
            artifact = self._first_artifact(task_state, "inline_log_event")
            compiled = getattr(task_state, "compiled_input", {}) or objective_contract.get("compiled_input") or {}
            params["raw_log_text"] = raw
            params["compiled_input_ref"] = compiled.get("compiled_input_id") or objective_contract.get("compiled_input_ref") or ""
            params["raw_event_ref"] = (artifact or {}).get("raw_event_ref") or compiled.get("artifact_ref")
            params["parsed_fields"] = (artifact or {}).get("fields") or ((compiled.get("parser") or {}).get("parsed_fields") if isinstance(compiled, dict) else {}) or {}
            params["evidence_scope"] = "pasted_artifact_only"
            sources.update({"raw_log_text": "message", "compiled_input_ref": "compiler", "raw_event_ref": "compiler", "parsed_fields": "raw_log_parser"})
            if not params["raw_log_text"] and not params["parsed_fields"]:
                missing.append("raw_log_text")
                questions.append("Paste the raw network/security log event to analyze.")
        elif capability == "email.parse.inline":
            params.update(self._bind_inline_email(raw, task_state))
            sources.update({key: "inline_email_message" for key in params})
            if not (params.get("raw_email_text") or params.get("sender") or params.get("urls")):
                missing.append("raw_email_text")
                questions.append("Paste the raw email, headers, or at least sender, subject, URL, and body snippet for phishing triage.")
        elif capability == "email.analyze":
            inline = self._first_artifact(task_state, "inline_email")
            if inline:
                params["inline_email_ref"] = inline.get("artifact_id")
                params["inline_email"] = inline
                sources["inline_email_ref"] = "task_state.artifacts"
            else:
                path = self._extract_clean_path(raw)
                if path:
                    params["file_path"] = path
                    sources["file_path"] = "message.path"
                else:
                    missing.append("file_path_or_inline_email_ref")
        elif capability == "file.analyze.static":
            artifact = self._first_artifact(task_state, "local_path_reference")
            path = str((artifact or {}).get("file_path") or self._extract_clean_path(raw) or "").strip()
            if path:
                params["file_path"] = path
                sources["file_path"] = "task_state.artifacts" if artifact else "message.path"
            hash_value = self._first_entity_value(task_state, "hash")
            if hash_value:
                params["hash"] = hash_value
                sources["hash"] = "task_state.entities"
            declared_missing = bool((artifact or {}).get("declared_missing")) or any(token in raw.lower() for token in ("not uploaded", "was not uploaded", "haven't uploaded", "not upload"))
            params["declared_missing"] = declared_missing
            params.setdefault("safe_static_only", True)
            if not path and not hash_value:
                missing.append("file_path_or_hash")
                questions.append("Upload/select the malware sample or provide its hash for IOC-only triage.")
        elif capability == "ioc.enrich":
            entity = self._first_ioc_entity(task_state)
            if entity:
                params["ioc_value"] = entity.get("value")
                params["ioc"] = entity.get("value")
                params["ioc_type"] = entity.get("type")
                sources["ioc_value"] = "task_state.entities"
            else:
                missing.append("ioc_value")
        elif capability == "ioc.extract":
            params["text"] = raw
            sources["text"] = "message"
        elif capability in {"case.summarize", "task.summarize"}:
            params["task_ref"] = getattr(task_state, "parent_task_id", None) or getattr(task_state, "task_id", "")
            params["summary_scope"] = "prior_task_findings"
        elif capability.startswith("ir."):
            params.update(self._bind_ir_action(capability, raw, task_state))
            sources.update({key: "message_or_task_state" for key in params})
        else:
            params.setdefault("objective", getattr(task_state, "analyst_objective", raw))

        invalid = self._invalid_scalar_leaks(params, raw, capability)
        if invalid:
            questions.append("Please provide typed values rather than a full sentence for: " + ", ".join(invalid) + ".")
        needs_clarification = bool(missing or invalid or questions)
        return ParameterBindingResult(
            action_id=action_obj.action_id,
            params=params,
            missing_required=missing,
            invalid_fields=invalid,
            field_sources=sources,
            confidence=0.55 if needs_clarification else 0.9,
            needs_clarification=needs_clarification,
            clarification_questions=list(dict.fromkeys(questions)),
        )

    def _bind_log_search(self, raw: str, task_state: Any, objective: Dict[str, Any]) -> Dict[str, Any]:
        timerange = dict(getattr(task_state, "timerange", {}) or objective.get("timerange") or {})
        backend = self._first_backend(task_state, objective)
        entities = list(getattr(task_state, "entities", []) or objective.get("entities") or [])
        query_intent = self._log_query_intent(raw)
        compiled = getattr(task_state, "compiled_input", {}) or objective.get("compiled_input") or {}
        alert_fields = ((compiled.get("parser") or {}).get("parsed_fields") if isinstance(compiled, dict) else {}) or {}
        facets = ["timestamp", "user", "host", "source_ip", "outcome", "event_code"] if "logon" in raw.lower() or "login" in raw.lower() else ["timestamp", "src_ip", "dest_ip", "action", "service", "policy", "raw_event"]
        if alert_fields:
            facets = ["timestamp", "host", "event_code", "process", "command_line", "rule_name", "severity", "raw_event"]
        params = {
            "query_intent": query_intent,
            "query": query_intent,
            "entities": entities,
            "backend": backend,
            "timerange": timerange.get("effective") or timerange.get("value") or timerange.get("requested") or "24h",
            "requested_timerange": timerange,
            "max_results": 100,
            "required_facets": facets,
        }
        if alert_fields:
            params["alert_fields"] = alert_fields
            params["host"] = alert_fields.get("host") or self._first_entity_value(task_state, "host")
            params["command_line"] = alert_fields.get("command_line")
            params["event_id"] = alert_fields.get("event_id")
            params["rule_name"] = alert_fields.get("rule_name")
        if backend in {"splunk", "siem"}:
            params.setdefault("index", "*")
        if backend in {"fortigate", "fortinet", "firewall"}:
            params.setdefault("sourcetype", "fortigate")
        return params

    def _bind_inline_email(self, raw: str, task_state: Any) -> Dict[str, Any]:
        artifact = self._first_artifact(task_state, "inline_email") or {}
        emails = re.findall(r"[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,}", raw)
        urls = self._URL_RE.findall(raw)
        subject = artifact.get("subject") or self._extract_labeled(raw, "subject")
        sender = artifact.get("sender") or self._extract_labeled(raw, "from") or (emails[0].lower() if emails else "")
        recipient = artifact.get("recipient") or self._extract_labeled(raw, "to")
        return {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "urls": list(dict.fromkeys(artifact.get("urls") or urls)),
            "body": artifact.get("body") or raw,
            "headers": artifact.get("headers") or {},
            "attachments": artifact.get("attachments") or [],
            "raw_email_text": artifact.get("raw_text") or raw,
            "inline_email_ref": artifact.get("artifact_id"),
        }

    def _bind_ir_action(self, capability: str, raw: str, task_state: Any) -> Dict[str, Any]:
        params = {"approval_required": True, "evidence_refs": [], "requested_action": capability}
        lowered = raw.lower()
        if "host" in capability:
            params.update({"target_type": "host", "target": self._first_entity_value(task_state, "host") or self._after_token(raw, "host") or ""})
        elif "user" in capability:
            params.update({"target_type": "user", "target": self._first_entity_value(task_state, "user") or self._after_token(raw, "user") or ""})
        elif "network" in capability or "block" in lowered:
            params.update({"target_type": "ip", "target": self._first_entity_value(task_state, "ip") or ""})
        else:
            params.update({"target_type": "action", "target": raw[:120]})
        return params

    @staticmethod
    def _first_artifact(task_state: Any, artifact_type: str) -> Dict[str, Any]:
        for item in getattr(task_state, "artifacts", []) or []:
            if isinstance(item, dict) and item.get("type") == artifact_type:
                return item
        return {}

    @staticmethod
    def _first_entity_value(task_state: Any, entity_type: str) -> str:
        for item in getattr(task_state, "entities", []) or []:
            if isinstance(item, dict) and item.get("type") == entity_type and item.get("value"):
                return str(item.get("value"))
        return ""

    def _first_ioc_entity(self, task_state: Any) -> Dict[str, Any]:
        for wanted in ("ip", "domain", "url", "hash", "cve"):
            for item in getattr(task_state, "entities", []) or []:
                if isinstance(item, dict) and item.get("type") == wanted and item.get("value"):
                    return item
        return {}

    @staticmethod
    def _first_backend(task_state: Any, objective: Dict[str, Any]) -> str:
        backends = list(getattr(task_state, "requested_backends", []) or objective.get("requested_backends") or [])
        return str(backends[0]).lower() if backends else ""

    def _extract_clean_path(self, raw: str) -> str:
        match = self._WIN_PATH_RE.search(raw)
        if match:
            value = match.group(1).strip().rstrip(".,;:)")
            return value
        return ""

    @staticmethod
    def _extract_labeled(raw: str, label: str) -> str:
        match = re.search(rf"\b{re.escape(label)}\s*:\s*([^\n;,]+)", raw, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _after_token(raw: str, token: str) -> str:
        match = re.search(rf"\b{re.escape(token)}\s+([A-Za-z0-9_.\-]+)", raw, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _log_query_intent(raw: str) -> str:
        lowered = raw.lower()
        if "failed" in lowered and ("success" in lowered or "successful" in lowered):
            return "failed logons followed by success"
        if "beacon" in lowered:
            return "outbound beaconing"
        if "alert" in lowered and ("wmi" in lowered or "get-wmiobject" in lowered):
            return "investigate WMI system information discovery alert around host, Event ID, command line, and rule context"
        if "hunt" in lowered:
            return "broad suspicious activity hunt"
        return re.sub(r"\s+", " ", raw).strip()[:240] or "security log search"

    @staticmethod
    def _invalid_scalar_leaks(params: Dict[str, Any], raw: str, capability: str) -> List[str]:
        invalid: List[str] = []
        raw_norm = re.sub(r"\s+", " ", raw).strip().lower()
        for key in ("ioc", "ioc_value", "file_path"):
            value = str(params.get(key) or "").strip()
            if not value:
                continue
            value_norm = re.sub(r"\s+", " ", value).lower()
            if len(value_norm.split()) > 7 or (raw_norm and value_norm == raw_norm and capability not in {"ioc.extract"}):
                invalid.append(key)
        if params.get("file_path") and str(params["file_path"]).startswith("http"):
            invalid.append("file_path")
        return list(dict.fromkeys(invalid))
