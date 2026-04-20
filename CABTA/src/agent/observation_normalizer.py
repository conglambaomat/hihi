"""Observation normalization for tool and MCP results."""

from __future__ import annotations

import copy
import ipaddress
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .log_observation_normalizer import LogObservationNormalizer
from .observation_type_inference import infer_generic_observation_type


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Observation:
    observation_id: str
    tool_name: str
    observation_type: str
    timestamp: Optional[str]
    summary: str
    quality: float
    source_kind: str
    source_paths: List[str]
    entities: List[Dict[str, Any]]
    facts: Dict[str, Any]
    raw_ref: Dict[str, Any]
    schema_version: str = "typed-observation/v1"
    fact_family: str = "generic"
    produced_at: str = field(default_factory=_now_iso)
    extraction_method: str = "normalizer"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["quality"] = round(float(payload.get("quality", 0.0)), 3)
        return payload


class ObservationNormalizer:
    """Convert heterogeneous tool outputs into typed, provenance-rich observations."""

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    _FACT_FAMILY_SCHEMAS: Dict[str, Dict[str, Any]] = {
        "ioc": {
            "family": "ioc",
            "version": "fact-family/ioc/v1",
            "canonical_fields": ["verdict", "severity", "score", "ioc", "ip", "domain", "url", "hash"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "network": {
            "family": "network",
            "version": "fact-family/network/v1",
            "canonical_fields": ["host", "user", "session_id", "source_ip", "dest_ip", "domain", "url", "action"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "email": {
            "family": "email",
            "version": "fact-family/email/v1",
            "canonical_fields": ["sender", "recipient", "domain", "attachment", "url", "verdict", "severity"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "log": {
            "family": "log",
            "version": "fact-family/log/v1",
            "canonical_fields": ["timestamp", "action", "user", "host", "session_id", "source_ip", "dest_ip", "process_name", "command_line"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "file": {
            "family": "file",
            "version": "fact-family/file/v1",
            "canonical_fields": ["file_name", "path", "process_name", "hash", "domain", "url", "verdict", "severity"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "vulnerability": {
            "family": "vulnerability",
            "version": "fact-family/vulnerability/v1",
            "canonical_fields": ["host", "asset", "alert", "severity", "cve", "verdict"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "correlation": {
            "family": "correlation",
            "version": "fact-family/correlation/v1",
            "canonical_fields": ["summary", "results_count", "source_ip", "dest_ip", "domain", "url"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
        "generic": {
            "family": "generic",
            "version": "fact-family/generic/v1",
            "canonical_fields": ["summary"],
            "required_provenance": ["observation_id", "tool_name", "source_kind", "source_paths", "produced_at", "extraction_method"],
        },
    }

    def __init__(self) -> None:
        self._log_normalizer = LogObservationNormalizer()

    def normalize(
        self,
        *,
        session_id: str,
        tool_name: str,
        params: Optional[Dict[str, Any]],
        result: Any,
        step_number: int,
    ) -> Dict[str, Any]:
        payload = self._payload(result)
        tool_lower = str(tool_name or "").lower()
        observations: List[Observation] = []
        obs_dicts: List[Dict[str, Any]]

        if tool_lower == "search_logs":
            obs_dicts = self._log_normalizer.normalize(
                session_id=session_id,
                tool_name=tool_name,
                params=params or {},
                payload=payload,
                step_number=step_number,
            )
        elif tool_lower == "investigate_ioc" or "ioc" in tool_lower or "threat" in tool_lower or "whois" in tool_lower:
            observations.extend(self._normalize_ioc_enrichment(session_id, tool_name, params or {}, payload, step_number))
        elif tool_lower == "analyze_email" or "email" in tool_lower:
            observations.extend(self._normalize_email_delivery(session_id, tool_name, params or {}, payload, step_number))
        elif tool_lower in {"analyze_malware", "yara_scan"} or "sandbox" in tool_lower or "malware" in tool_lower:
            observations.extend(self._normalize_file_or_sandbox(session_id, tool_name, params or {}, payload, step_number))
        elif tool_lower == "correlate_findings":
            correlation_facts = self._strip_none(copy.deepcopy(payload if isinstance(payload, dict) else {"value": payload}))
            observations.append(
                self._make_observation(
                    session_id=session_id,
                    tool_name=tool_name,
                    step_number=step_number,
                    index=0,
                    observation_type=infer_generic_observation_type(correlation_facts),
                    summary=self._summary_for_payload(tool_name, payload, params or {}),
                    quality=0.72,
                    source_kind="tool_result",
                    source_paths=["result"],
                    entities=self._entities_from_value(payload, "result"),
                    facts=correlation_facts,
                    params=params or {},
                    result=result,
                )
            )
        else:
            observations.append(
                self._make_observation(
                    session_id=session_id,
                    tool_name=tool_name,
                    step_number=step_number,
                    index=0,
                    observation_type=infer_generic_observation_type(payload),
                    summary=self._summary_for_payload(tool_name, payload, params or {}),
                    quality=self._generic_quality(payload),
                    source_kind="tool_result",
                    source_paths=["result"],
                    entities=self._entities_from_value(payload, "result") + self._entities_from_value(params or {}, "params"),
                    facts=self._strip_none(copy.deepcopy(payload if isinstance(payload, dict) else {"value": payload})),
                    params=params or {},
                    result=result,
                )
            )

        if tool_lower != "search_logs":
            obs_dicts = [item.to_dict() for item in observations]
        obs_dicts = [self._enrich_observation_dict(item) for item in obs_dicts]
        return {
            "observations": obs_dicts,
            "accepted_facts_delta": self._accepted_facts_delta(obs_dicts),
            "evidence_quality_summary": self._evidence_quality_summary(obs_dicts),
            "fact_family_schemas": self._fact_family_schema_summary(obs_dicts),
        }

    def _normalize_search_logs(
        self,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        payload: Any,
        step_number: int,
    ) -> List[Observation]:
        if not isinstance(payload, dict):
            return [
                self._make_observation(
                    session_id=session_id,
                    tool_name=tool_name,
                    step_number=step_number,
                    index=0,
                    observation_type="correlation_observation",
                    summary=f"{tool_name} returned a non-structured log hunt payload.",
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
        observations: List[Observation] = []
        for index, row in enumerate(rows[:25]):
            if not isinstance(row, dict):
                continue
            observation_type = self._classify_log_row(row)
            entities = self._entities_from_value(row, f"result.results[{index}]")
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
                    entities=entities,
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

    def _normalize_ioc_enrichment(
        self,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        payload: Any,
        step_number: int,
    ) -> List[Observation]:
        facts = self._strip_none(copy.deepcopy(payload if isinstance(payload, dict) else {"value": payload}))
        return [
            self._make_observation(
                session_id=session_id,
                tool_name=tool_name,
                step_number=step_number,
                index=0,
                observation_type="ioc_enrichment",
                summary=self._summary_for_payload(tool_name, payload, params),
                quality=self._generic_quality(payload),
                source_kind="tool_result",
                source_paths=["result"],
                entities=self._entities_from_value(facts, "result") + self._entities_from_value(params, "params"),
                facts=facts,
                params=params,
                result=payload,
            )
        ]

    def _normalize_email_delivery(
        self,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        payload: Any,
        step_number: int,
    ) -> List[Observation]:
        facts = self._strip_none(copy.deepcopy(payload if isinstance(payload, dict) else {"value": payload}))
        return [
            self._make_observation(
                session_id=session_id,
                tool_name=tool_name,
                step_number=step_number,
                index=0,
                observation_type="email_delivery",
                summary=self._summary_for_payload(tool_name, payload, params),
                quality=max(0.55, self._generic_quality(payload)),
                source_kind="tool_result",
                source_paths=["result"],
                entities=self._entities_from_value(facts, "result") + self._entities_from_value(params, "params"),
                facts=facts,
                params=params,
                result=payload,
            )
        ]

    def _normalize_file_or_sandbox(
        self,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        payload: Any,
        step_number: int,
    ) -> List[Observation]:
        observation_type = "sandbox_behavior" if "sandbox" in str(tool_name).lower() else "file_execution"
        facts = self._strip_none(copy.deepcopy(payload if isinstance(payload, dict) else {"value": payload}))
        return [
            self._make_observation(
                session_id=session_id,
                tool_name=tool_name,
                step_number=step_number,
                index=0,
                observation_type=observation_type,
                summary=self._summary_for_payload(tool_name, payload, params),
                quality=max(0.55, self._generic_quality(payload)),
                source_kind="tool_result",
                source_paths=["result"],
                entities=self._entities_from_value(facts, "result") + self._entities_from_value(params, "params"),
                facts=facts,
                params=params,
                result=payload,
            )
        ]

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
    ) -> Observation:
        observation_id = f"obs:{session_id}:{step_number}:{index}:{tool_name}:{observation_type}".lower()
        deduped_entities = self._dedupe_entities(entities)
        normalized_facts = self._strip_none(facts)
        observation_timestamp = str(
            normalized_facts.get("timestamp")
            or normalized_facts.get("@timestamp")
            or normalized_facts.get("time")
            or _now_iso()
        )
        return Observation(
            observation_id=observation_id,
            tool_name=tool_name,
            observation_type=observation_type,
            timestamp=observation_timestamp,
            summary=summary,
            quality=max(0.0, min(1.0, float(quality))),
            source_kind=source_kind,
            source_paths=source_paths,
            entities=deduped_entities,
            facts=normalized_facts,
            raw_ref={
                "params": copy.deepcopy(params),
                "result_preview": self._preview_result(result),
            },
            fact_family=self._fact_family_for_observation_type(observation_type),
            produced_at=_now_iso(),
            extraction_method="normalizer",
        )

    def _payload(self, result: Any) -> Any:
        if isinstance(result, dict) and isinstance(result.get("result"), dict):
            return result.get("result")
        return result

    def _enrich_observation_dict(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(observation or {})
        observation_type = str(enriched.get("observation_type") or "")
        fact_family = str(
            enriched.get("fact_family") or self._fact_family_for_observation_type(observation_type)
        )
        source_paths = list(enriched.get("source_paths", []) or [])
        entities = list(enriched.get("entities", []) or [])
        quality = round(float(enriched.get("quality", 0.0) or 0.0), 3)

        enriched.setdefault("schema_version", "typed-observation/v1")
        enriched.setdefault("fact_family", fact_family)
        enriched.setdefault("produced_at", _now_iso())
        enriched.setdefault("extraction_method", "normalizer")
        enriched.setdefault(
            "typed_fact",
            {
                "family": fact_family,
                "type": observation_type or "unknown",
                "summary": str(enriched.get("summary") or "").strip(),
                "timestamp": enriched.get("timestamp"),
                "quality": quality,
                "source_kind": enriched.get("source_kind"),
                "schema": self._fact_family_schema(fact_family),
            },
        )
        enriched.setdefault(
            "provenance",
            {
                "observation_id": enriched.get("observation_id"),
                "tool_name": enriched.get("tool_name"),
                "source_kind": enriched.get("source_kind"),
                "source_paths": source_paths,
                "produced_at": enriched.get("produced_at"),
                "extraction_method": enriched.get("extraction_method"),
                "entity_count": len([entity for entity in entities if isinstance(entity, dict)]),
            },
        )
        enriched.setdefault(
            "entity_ids",
            [
                f"{entity.get('type')}:{entity.get('value')}".lower()
                for entity in entities
                if isinstance(entity, dict) and entity.get("type") and entity.get("value")
            ][:12],
        )
        enriched.setdefault(
            "quality_semantics",
            {
                "score": quality,
                "band": self._quality_band(quality),
                "is_strong": quality >= 0.72,
                "is_actionable": quality >= 0.68,
                "family": fact_family,
                "normalization_version": "quality-semantics/v1",
            },
        )
        enriched.setdefault("quality_band", self._quality_band(quality))
        return enriched

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
        verdict = str(payload.get("verdict") or "").upper()
        severity = str(payload.get("severity") or "").upper()
        score = payload.get("threat_score", payload.get("score"))
        if verdict:
            if score is not None:
                return f"{tool_name} reported verdict={verdict} with score={score}."
            return f"{tool_name} reported verdict={verdict}."
        if severity:
            return f"{tool_name} reported severity={severity}."
        if "results_count" in payload:
            return f"{tool_name} returned {payload.get('results_count', 0)} matching records."
        indicators = []
        for key in ("ioc", "ip", "domain", "hash", "host", "user", "session_id"):
            value = payload.get(key) or params.get(key)
            if value:
                indicators.append(f"{key}={value}")
        if indicators:
            return f"{tool_name} observed " + ", ".join(indicators[:4]) + "."
        if payload.get("error"):
            return f"{tool_name} failed with error={str(payload.get('error'))[:160]}."
        return f"{tool_name} returned additional investigative evidence."

    def _generic_quality(self, payload: Any) -> float:
        if not isinstance(payload, dict):
            return 0.4
        quality = 0.45
        if payload.get("verdict") or payload.get("severity"):
            quality += 0.2
        if isinstance(payload.get("score"), (int, float)) or isinstance(payload.get("threat_score"), (int, float)):
            quality += 0.1
        if payload.get("results") or payload.get("matches"):
            quality += 0.08
        if payload.get("error"):
            quality = 0.15
        return min(0.92, quality)

    def _accepted_facts_delta(self, observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        facts: List[Dict[str, Any]] = []
        for observation in observations:
            if float(observation.get("quality", 0.0) or 0.0) < 0.68:
                continue
            entity_ids = [
                f"{entity.get('type')}:{entity.get('value')}".lower()
                for entity in observation.get("entities", [])
                if isinstance(entity, dict) and entity.get("type") and entity.get("value")
            ][:8]
            facts.append(
                {
                    "observation_id": observation.get("observation_id"),
                    "summary": observation.get("summary"),
                    "observation_type": observation.get("observation_type"),
                    "fact_family": observation.get("fact_family") or self._fact_family_for_observation_type(
                        str(observation.get("observation_type") or "")
                    ),
                    "quality": observation.get("quality"),
                    "timestamp": observation.get("timestamp"),
                    "produced_at": observation.get("produced_at"),
                    "source_kind": observation.get("source_kind"),
                    "source_paths": list(observation.get("source_paths", []) or []),
                    "extraction_method": observation.get("extraction_method") or "normalizer",
                    "entity_ids": entity_ids,
                    "typed_fact": {
                        "family": observation.get("fact_family") or self._fact_family_for_observation_type(
                            str(observation.get("observation_type") or "")
                        ),
                        "type": observation.get("observation_type"),
                        "summary": observation.get("summary"),
                        "quality": observation.get("quality"),
                        "schema": self._fact_family_schema(
                            str(
                                observation.get("fact_family")
                                or self._fact_family_for_observation_type(str(observation.get("observation_type") or ""))
                            )
                        ),
                    },
                    "provenance_ref": {
                        "observation_id": observation.get("observation_id"),
                        "tool_name": observation.get("tool_name"),
                        "source_kind": observation.get("source_kind"),
                        "source_paths": list(observation.get("source_paths", []) or []),
                        "produced_at": observation.get("produced_at"),
                    },
                }
            )
        return facts[-12:]

    def _evidence_quality_summary(self, observations: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not observations:
            return {
                "observation_count": 0,
                "average_quality": 0.0,
                "strong_observation_count": 0,
                "typed_observations": {},
                "fact_families": {},
                "typed_quality_breakdown": {},
                "quality_bands": {},
                "provenance_coverage": {
                    "with_source_paths": 0,
                    "with_entity_ids": 0,
                },
            }
        qualities = [float(item.get("quality", 0.0) or 0.0) for item in observations]
        typed: Dict[str, int] = {}
        fact_families: Dict[str, int] = {}
        typed_quality_breakdown: Dict[str, Dict[str, Any]] = {}
        quality_bands: Dict[str, int] = {}
        with_source_paths = 0
        with_entity_ids = 0
        for observation in observations:
            obs_type = str(observation.get("observation_type") or "unknown")
            typed[obs_type] = typed.get(obs_type, 0) + 1
            fact_family = str(
                observation.get("fact_family")
                or self._fact_family_for_observation_type(obs_type)
                or "generic"
            )
            fact_families[fact_family] = fact_families.get(fact_family, 0) + 1

            bucket = typed_quality_breakdown.setdefault(
                obs_type,
                {"count": 0, "average_quality": 0.0, "_quality_total": 0.0},
            )
            quality = float(observation.get("quality", 0.0) or 0.0)
            bucket["count"] += 1
            bucket["_quality_total"] += quality
            band = str(observation.get("quality_band") or self._quality_band(quality))
            quality_bands[band] = quality_bands.get(band, 0) + 1

            if observation.get("source_paths"):
                with_source_paths += 1
            if observation.get("entity_ids") or observation.get("entities"):
                with_entity_ids += 1

        for bucket in typed_quality_breakdown.values():
            count = int(bucket.get("count", 0) or 0)
            total = float(bucket.pop("_quality_total", 0.0) or 0.0)
            bucket["average_quality"] = round(total / max(count, 1), 3)

        return {
            "observation_count": len(observations),
            "average_quality": round(sum(qualities) / max(len(qualities), 1), 3),
            "strong_observation_count": sum(1 for quality in qualities if quality >= 0.72),
            "typed_observations": typed,
            "fact_families": fact_families,
            "typed_quality_breakdown": typed_quality_breakdown,
            "quality_bands": quality_bands,
            "provenance_coverage": {
                "with_source_paths": with_source_paths,
                "with_entity_ids": with_entity_ids,
            },
        }

    def _fact_family_schema(self, fact_family: str) -> Dict[str, Any]:
        family = str(fact_family or "generic").strip().lower() or "generic"
        schema = self._FACT_FAMILY_SCHEMAS.get(family, self._FACT_FAMILY_SCHEMAS["generic"])
        return copy.deepcopy(schema)

    def _fact_family_schema_summary(self, observations: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        families = {
            str(
                observation.get("fact_family")
                or self._fact_family_for_observation_type(str(observation.get("observation_type") or ""))
                or "generic"
            ).strip().lower()
            for observation in observations
            if isinstance(observation, dict)
        }
        return {family: self._fact_family_schema(family) for family in sorted(families)}

    def _fact_family_for_observation_type(self, observation_type: str) -> str:
        normalized = str(observation_type or "").strip().lower()
        if normalized in {"ioc_enrichment"}:
            return "ioc"
        if normalized in {"network_event"}:
            return "network"
        if normalized in {"email_delivery"}:
            return "email"
        if normalized in {"auth_event", "process_event", "host_timeline_event"}:
            return "log"
        if normalized in {"file_execution", "sandbox_behavior"}:
            return "file"
        if normalized in {"vulnerability_exposure"}:
            return "vulnerability"
        if normalized in {"correlation_observation"}:
            return "correlation"
        return "generic"

    @staticmethod
    def _quality_band(quality: float) -> str:
        score = float(quality or 0.0)
        if score >= 0.85:
            return "high"
        if score >= 0.68:
            return "medium"
        if score >= 0.4:
            return "low"
        return "weak"

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
        if self._HASH_RE.fullmatch(text):
            return [self._entity_payload("hash", text.lower(), source_path, confidence=0.92)]
        if text.lower().startswith("http://") or text.lower().startswith("https://"):
            return [self._entity_payload("url", text, source_path, confidence=0.92)]
        if text.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs")):
            return [self._entity_payload("process", os.path.basename(text), source_path, confidence=0.72, attributes={"path": text})]

        entities.extend(self._entity_payload("ip", item, source_path, confidence=0.78, attributes=self._ip_attributes(item)) for item in self._IP_RE.findall(text) if self._is_ip(item))
        entities.extend(self._entity_payload("domain", item.lower(), source_path, confidence=0.72) for item in self._DOMAIN_RE.findall(text))
        entities.extend(self._entity_payload("email", item.lower(), source_path, confidence=0.8) for item in self._EMAIL_RE.findall(text))
        entities.extend(self._entity_payload("hash", item.lower(), source_path, confidence=0.78) for item in self._HASH_RE.findall(text))
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
        if "hash" in key_hint or key_hint.endswith(("sha256", "sha1", "md5")):
            return [self._entity_payload("hash", text.lower(), key_hint, confidence=0.88)]
        return []

    def _entity_payload(
        self,
        entity_type: str,
        value: str,
        source_path: str,
        *,
        confidence: float,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "type": entity_type,
            "value": value,
            "label": value,
            "source_path": source_path,
            "extraction_method": "normalizer",
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
