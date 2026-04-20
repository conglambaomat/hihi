"""Specialized normalization for log-hunt results."""

from __future__ import annotations

import copy
import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from .observation_type_inference import infer_generic_observation_type


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LogObservationNormalizer:
    """Convert log rows into auth/process/network/session/host observations."""

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")

    def normalize(
        self,
        *,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        payload: Any,
        step_number: int,
    ) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return [
                self._make_observation(
                    session_id=session_id,
                    tool_name=tool_name,
                    step_number=step_number,
                    index=0,
                    observation_type="correlation_observation",
                    summary=f"{tool_name} returned a non-structured log-hunt payload.",
                    quality=0.35,
                    source_kind="tool_result",
                    source_paths=["result"],
                    entities=[],
                    facts={"raw": str(payload)},
                    params=params,
                    result=payload,
                )
            ]

        rows = payload.get("results", [])
        observations: List[Dict[str, Any]] = []
        for index, row in enumerate(rows[:25]):
            if not isinstance(row, dict):
                continue
            observation_type = self._classify_log_row(row)
            facts = self._normalize_log_facts(row, observation_type)
            observations.append(
                self._make_observation(
                    session_id=session_id,
                    tool_name=tool_name,
                    step_number=step_number,
                    index=index,
                    observation_type=observation_type,
                    summary=self._log_row_summary(row, observation_type),
                    quality=self._log_row_quality(row, observation_type),
                    source_kind="log_row",
                    source_paths=[f"result.results[{index}]"],
                    entities=self._entities_from_value(row, f"result.results[{index}]"),
                    facts=facts,
                    params=params,
                    result=row,
                )
            )

        aggregate_facts = self._strip_none(
            {
                "query": params.get("query"),
                "timerange": payload.get("timerange") or params.get("timerange"),
                "status": payload.get("status"),
                "results_count": payload.get("results_count", len(rows) if isinstance(rows, list) else 0),
                "suspicious_indicators": payload.get("suspicious_indicators", []),
                "suspicious_files": payload.get("suspicious_files", []),
                "suspicious_executables": payload.get("suspicious_executables", []),
                "query_planner": payload.get("query_planner", {}),
                "message": payload.get("message"),
            }
        )
        observations.append(
            self._make_observation(
                session_id=session_id,
                tool_name=tool_name,
                step_number=step_number,
                index=999,
                observation_type=infer_generic_observation_type(aggregate_facts),
                summary=self._summary_for_payload(tool_name, payload, params),
                quality=0.7 if aggregate_facts.get("results_count", 0) else 0.45,
                source_kind="tool_result",
                source_paths=["result"],
                entities=self._entities_from_value(aggregate_facts, "result"),
                facts=aggregate_facts,
                params=params,
                result=payload,
            )
        )
        return observations

    def _classify_log_row(self, row: Dict[str, Any]) -> str:
        keys = {str(key).lower() for key in row.keys()}
        if {"user", "username", "account"} & keys and {"src_ip", "source_ip", "client_ip", "session_id", "logon_id", "action"} & keys:
            return "auth_event"
        if {"process", "process_name", "image", "image_path", "cmdline", "command_line"} & keys:
            return "process_event"
        if {"dest_ip", "destination_ip", "remote_ip", "domain", "url"} & keys:
            return "network_event"
        if {"host", "hostname", "device"} & keys:
            return "host_timeline_event"
        return "correlation_observation"

    def _normalize_log_facts(self, row: Dict[str, Any], observation_type: str) -> Dict[str, Any]:
        facts = self._strip_none(
            {
                "timestamp": row.get("timestamp") or row.get("@timestamp") or row.get("_time"),
                "action": row.get("action") or row.get("event") or row.get("event_name"),
                "user": row.get("user") or row.get("username") or row.get("account"),
                "host": row.get("host") or row.get("hostname") or row.get("device"),
                "session_id": row.get("session_id") or row.get("logon_id") or row.get("session"),
                "source_ip": row.get("source_ip") or row.get("src_ip") or row.get("client_ip"),
                "dest_ip": row.get("dest_ip") or row.get("destination_ip") or row.get("remote_ip"),
                "domain": row.get("domain"),
                "url": row.get("url"),
                "process_name": row.get("process_name") or row.get("process") or row.get("image"),
                "process_path": row.get("image_path") or row.get("process_path"),
                "command_line": row.get("cmdline") or row.get("command_line"),
                "observation_type": observation_type,
            }
        )
        facts["raw_row"] = copy.deepcopy(row)
        return facts

    def _log_row_summary(self, row: Dict[str, Any], observation_type: str) -> str:
        user = row.get("user") or row.get("username") or row.get("account")
        host = row.get("host") or row.get("hostname") or row.get("device")
        source_ip = row.get("source_ip") or row.get("src_ip") or row.get("client_ip")
        dest_ip = row.get("dest_ip") or row.get("destination_ip") or row.get("remote_ip")
        process_name = row.get("process_name") or row.get("process") or row.get("image")
        session_id = row.get("session_id") or row.get("logon_id") or row.get("session")
        if observation_type == "auth_event":
            parts = [f"user={user}" if user else "", f"host={host}" if host else "", f"session={session_id}" if session_id else "", f"source_ip={source_ip}" if source_ip else ""]
            return "Auth telemetry: " + ", ".join(part for part in parts if part)
        if observation_type == "process_event":
            parts = [f"process={process_name}" if process_name else "", f"host={host}" if host else "", f"user={user}" if user else "", f"dest_ip={dest_ip}" if dest_ip else ""]
            return "Process telemetry: " + ", ".join(part for part in parts if part)
        if observation_type == "network_event":
            parts = [f"host={host}" if host else "", f"user={user}" if user else "", f"dest_ip={dest_ip}" if dest_ip else "", f"domain={row.get('domain')}" if row.get("domain") else ""]
            return "Network telemetry: " + ", ".join(part for part in parts if part)
        return "Host telemetry row observed."

    def _log_row_quality(self, row: Dict[str, Any], observation_type: str) -> float:
        quality = 0.52
        if observation_type in {"auth_event", "process_event", "network_event"}:
            quality += 0.18
        if row.get("host") or row.get("hostname"):
            quality += 0.08
        if row.get("user") or row.get("username"):
            quality += 0.08
        if row.get("session_id") or row.get("logon_id"):
            quality += 0.06
        if row.get("process_name") or row.get("image") or row.get("dest_ip") or row.get("domain"):
            quality += 0.06
        return min(0.96, quality)

    def _summary_for_payload(self, tool_name: str, payload: Any, params: Dict[str, Any]) -> str:
        if not isinstance(payload, dict):
            return f"{tool_name} returned a non-structured observation."
        if "results_count" in payload:
            return f"{tool_name} returned {payload.get('results_count', 0)} matching log records."
        if payload.get("message"):
            return str(payload.get("message"))
        if params.get("query"):
            return f"{tool_name} executed a focused hunt query for the current investigation."
        return f"{tool_name} returned log-derived investigative evidence."

    def _make_observation(
        self,
        *,
        session_id: str,
        tool_name: str,
        step_number: int,
        index: int,
        observation_type: str,
        summary: str,
        quality: float,
        source_kind: str,
        source_paths: List[str],
        entities: List[Dict[str, Any]],
        facts: Dict[str, Any],
        params: Dict[str, Any],
        result: Any,
    ) -> Dict[str, Any]:
        observation_id = f"obs:{session_id}:{step_number}:{index}:{tool_name}:{observation_type}".lower()
        return {
            "observation_id": observation_id,
            "tool_name": tool_name,
            "observation_type": observation_type,
            "timestamp": str(facts.get("timestamp") or facts.get("@timestamp") or facts.get("time") or _now_iso()),
            "summary": summary,
            "quality": round(max(0.0, min(1.0, float(quality))), 3),
            "source_kind": source_kind,
            "source_paths": list(source_paths),
            "entities": self._dedupe_entities(entities),
            "facts": self._strip_none(facts),
            "raw_ref": {
                "params": copy.deepcopy(params),
                "result_preview": self._preview_result(result),
            },
        }

    def _entities_from_value(self, value: Any, source_path: str) -> List[Dict[str, Any]]:
        entities: List[Dict[str, Any]] = []
        if value is None:
            return entities
        if isinstance(value, dict):
            for key, nested in value.items():
                entities.extend(self._entities_from_value(nested, f"{source_path}.{key}" if source_path else str(key)))
            return entities
        if isinstance(value, list):
            for index, item in enumerate(value):
                entities.extend(self._entities_from_value(item, f"{source_path}[{index}]"))
            return entities

        text = str(value).strip()
        if not text:
            return entities
        lowered_path = source_path.lower()

        hints = self._entity_from_key_hint(lowered_path, text)
        if hints:
            return hints

        if self._EMAIL_RE.fullmatch(text):
            return [
                self._entity_payload("email", text.lower(), source_path, confidence=0.92),
                self._entity_payload("user", text.lower(), source_path, confidence=0.78),
            ]
        if self._is_ip(text):
            return [self._entity_payload("ip", text, source_path, confidence=0.95, attributes=self._ip_attributes(text))]
        if self._DOMAIN_RE.fullmatch(text.lower()):
            return [self._entity_payload("domain", text.lower(), source_path, confidence=0.88)]
        if text.lower().startswith(("http://", "https://")):
            return [self._entity_payload("url", text, source_path, confidence=0.92)]
        if text.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs")):
            return [self._entity_payload("process", os.path.basename(text), source_path, confidence=0.72, attributes={"path": text})]

        entities.extend(self._entity_payload("ip", item, source_path, confidence=0.78, attributes=self._ip_attributes(item)) for item in self._IP_RE.findall(text) if self._is_ip(item))
        entities.extend(self._entity_payload("domain", item.lower(), source_path, confidence=0.72) for item in self._DOMAIN_RE.findall(text))
        entities.extend(self._entity_payload("email", item.lower(), source_path, confidence=0.8) for item in self._EMAIL_RE.findall(text))
        return entities

    def _entity_from_key_hint(self, key_hint: str, text: str) -> List[Dict[str, Any]]:
        if any(token in key_hint for token in ("user", "username", "account", "owner", "recipient", "sender")):
            return [self._entity_payload("user", text.lower() if "@" in text else text, key_hint, confidence=0.88)]
        if any(token in key_hint for token in ("email", "mail", "sender_address")):
            return [self._entity_payload("email", text.lower(), key_hint, confidence=0.9)]
        if any(token in key_hint for token in ("host", "hostname", "device", "computer", "workstation")):
            return [self._entity_payload("host", text, key_hint, confidence=0.88)]
        if any(token in key_hint for token in ("session", "logon_id", "login_id", "sid")):
            return [self._entity_payload("session", text, key_hint, confidence=0.9)]
        if any(token in key_hint for token in ("process", "process_name", "image", "cmdline", "command_line", "executable")):
            value = os.path.basename(text) if os.path.sep in text else text
            attrs = {"path": text} if os.path.sep in text else {}
            return [self._entity_payload("process", value, key_hint, confidence=0.82, attributes=attrs)]
        if any(token in key_hint for token in ("ip", "src_ip", "dest_ip", "remote_ip", "client_ip", "destination_ip", "source_ip")) and self._is_ip(text):
            return [self._entity_payload("ip", text, key_hint, confidence=0.95, attributes=self._ip_attributes(text))]
        if "domain" in key_hint:
            return [self._entity_payload("domain", text.lower(), key_hint, confidence=0.88)]
        if "url" in key_hint:
            return [self._entity_payload("url", text, key_hint, confidence=0.88)]
        return []

    def _entity_payload(
        self,
        entity_type: str,
        value: str,
        source_path: str,
        *,
        confidence: float,
        attributes: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {
            "type": entity_type,
            "value": value,
            "label": value,
            "source_path": source_path,
            "extraction_method": "log_normalizer",
            "confidence": round(float(confidence), 3),
            "attributes": attributes or {},
        }

    @staticmethod
    def _dedupe_entities(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            entity_type = str(entity.get("type") or "").strip().lower()
            value = str(entity.get("value") or "").strip()
            if not entity_type or not value:
                continue
            key = f"{entity_type}:{value.lower()}"
            existing = deduped.get(key, {})
            merged = {**existing, **entity}
            merged["confidence"] = max(float(existing.get("confidence", 0.0) or 0.0), float(entity.get("confidence", 0.0) or 0.0))
            deduped[key] = merged
        return list(deduped.values())

    @staticmethod
    def _strip_none(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in payload.items()
            if value not in (None, "", [], {})
        }

    @staticmethod
    def _preview_result(result: Any) -> Dict[str, Any]:
        if isinstance(result, dict):
            preview = {}
            for key in list(result.keys())[:12]:
                value = result.get(key)
                if isinstance(value, (str, int, float, bool)) or value is None:
                    preview[key] = value
                elif isinstance(value, list):
                    preview[key] = f"list[{len(value)}]"
                elif isinstance(value, dict):
                    preview[key] = f"dict[{len(value)}]"
                else:
                    preview[key] = type(value).__name__
            return preview
        return {"value": str(result)[:240]}

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    @staticmethod
    def _ip_attributes(value: str) -> Dict[str, Any]:
        try:
            ip_obj = ipaddress.ip_address(str(value))
            return {
                "is_private": ip_obj.is_private,
                "is_reserved": ip_obj.is_reserved,
                "is_loopback": ip_obj.is_loopback,
                "version": ip_obj.version,
            }
        except ValueError:
            return {}
