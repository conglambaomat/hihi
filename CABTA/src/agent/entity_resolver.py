"""Session-scoped entity resolution with provenance and relation strength."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EntityCandidate:
    type: str
    raw_value: str
    canonical_value: str
    label: str
    source_kind: str
    source_path: str
    extraction_method: str
    confidence: float
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EntityRecord:
    id: str
    type: str
    value: str
    canonical_value: str
    label: str
    confidence: float = 0.0
    aliases: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    source_paths: List[str] = field(default_factory=list)
    extraction_methods: List[str] = field(default_factory=list)
    observation_count: int = 0
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    first_seen_at: str = field(default_factory=_now_iso)
    last_seen_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "canonical_value": self.canonical_value,
            "label": self.label,
            "confidence": round(float(self.confidence), 3),
            "aliases": list(self.aliases),
            "attributes": dict(self.attributes),
            "source_paths": list(self.source_paths),
            "extraction_methods": list(self.extraction_methods),
            "observation_count": int(self.observation_count),
            "evidence_refs": list(self.evidence_refs),
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
        }


class EntityResolver:
    """Resolve entities and relationship basis from normalized observations."""

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    _CANONICAL_ENTITY_TYPES = (
        "user",
        "host",
        "asset",
        "session",
        "process",
        "file",
        "alert",
        "ip",
        "domain",
        "url",
        "hash",
        "email",
        "sender",
        "recipient",
    )
    _CANONICAL_RELATION_TYPES = (
        "belongs_to",
        "occurred_on",
        "authenticated_from",
        "executed_on",
        "derived_from",
        "connects_to",
        "spawned_process",
        "received_from",
        "received_attachment",
        "originates_from",
        "exposed_by",
        "co_observed",
    )
    _ENTITY_TYPE_ALIASES = {
        "hostname": "host",
        "device": "host",
        "computer": "host",
        "account": "user",
        "username": "user",
        "owner": "user",
        "mailbox": "recipient",
        "from_address": "sender",
        "to_address": "recipient",
        "src_ip": "ip",
        "dest_ip": "ip",
        "client_ip": "ip",
        "remote_ip": "ip",
    }
    _ENTITY_TYPE_FAMILIES = {
        "user": "identity",
        "sender": "identity",
        "recipient": "identity",
        "email": "identity",
        "host": "endpoint",
        "asset": "endpoint",
        "session": "execution",
        "process": "execution",
        "file": "artifact",
        "alert": "detection",
        "ip": "network",
        "domain": "network",
        "url": "network",
        "hash": "artifact",
    }

    def bootstrap(self, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        state = dict(existing or {})
        state.setdefault("schema_version", 2)
        state.setdefault("canonical_entity_types", list(self._CANONICAL_ENTITY_TYPES))
        state.setdefault("canonical_relation_types", list(self._CANONICAL_RELATION_TYPES))
        state.setdefault("entities", {})
        state.setdefault("relationships", [])
        state.setdefault("observations", [])
        state.setdefault("updated_at", _now_iso())
        return state

    def ingest_observation(
        self,
        entity_state: Optional[Dict[str, Any]],
        *,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        result: Any,
        step_number: int,
        evidence_ref: Dict[str, Any],
        observations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        state = self.bootstrap(entity_state)
        normalized_observations = observations or self._legacy_observations(
            session_id=session_id,
            tool_name=tool_name,
            params=params,
            result=result,
            step_number=step_number,
        )

        for observation in normalized_observations:
            if not isinstance(observation, dict):
                continue
            observation_id = str(observation.get("observation_id") or f"obs:{session_id}:{step_number}:{tool_name}").lower()
            candidates = self._candidates_from_observation(observation)
            entity_ids: List[str] = []
            candidate_by_type: Dict[str, List[str]] = {}
            for candidate in candidates:
                entity_id = self._upsert_entity(state, candidate, evidence_ref)
                entity_ids.append(entity_id)
                candidate_by_type.setdefault(candidate.type, []).append(entity_id)

            typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
            provenance = observation.get("provenance", {}) if isinstance(observation.get("provenance"), dict) else {}
            self._upsert_observation(
                state,
                {
                    "id": observation_id,
                    "step_number": step_number,
                    "tool_name": tool_name,
                    "observation_type": observation.get("observation_type"),
                    "fact_family": observation.get("fact_family") or typed_fact.get("family"),
                    "summary": observation.get("summary", evidence_ref.get("summary", "")),
                    "entity_ids": self._dedupe(entity_ids),
                    "source_paths": list(observation.get("source_paths", [])),
                    "timestamp": observation.get("timestamp") or evidence_ref.get("created_at") or _now_iso(),
                    "extraction_method": observation.get("extraction_method") or provenance.get("extraction_method"),
                    "source_kind": observation.get("source_kind") or provenance.get("source_kind"),
                },
            )

            explicit_relations = self._relations_from_observation(
                observation=observation,
                entity_ids_by_type=candidate_by_type,
                evidence_ref=evidence_ref,
            )
            if explicit_relations:
                for relation in explicit_relations:
                    self._upsert_relationship(state, relation)
            else:
                for relation in self._co_observed_relations(
                    entity_ids=self._dedupe(entity_ids),
                    source_paths=list(observation.get("source_paths", [])),
                    evidence_ref=evidence_ref,
                ):
                    self._upsert_relationship(state, relation)

        state["updated_at"] = _now_iso()
        return state

    def summarize_for_case_event(self, entity_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        state = self.bootstrap(entity_state)
        entities = list(state.get("entities", {}).values())
        relationships = list(state.get("relationships", []))
        return {
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "entities": entities[:20],
            "relationships": relationships[:30],
        }

    def _legacy_observations(
        self,
        *,
        session_id: str,
        tool_name: str,
        params: Dict[str, Any],
        result: Any,
        step_number: int,
    ) -> List[Dict[str, Any]]:
        payload = result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result
        entities = []
        for source_path, value in (("params", params), ("result", payload)):
            entities.extend(self._extract_entities(value, source_path))
        return [
            {
                "observation_id": f"obs:{session_id}:{step_number}:{tool_name}:legacy".lower(),
                "observation_type": "correlation_observation",
                "summary": f"{tool_name} observation",
                "source_kind": "legacy",
                "source_paths": ["params", "result"],
                "entities": entities,
                "facts": payload if isinstance(payload, dict) else {"value": str(payload)},
                "timestamp": evidence_ref_timestamp(result),
            }
        ]

    def _candidates_from_observation(self, observation: Dict[str, Any]) -> List[EntityCandidate]:
        entities = observation.get("entities", [])
        candidates: List[EntityCandidate] = []
        if isinstance(entities, list):
            for entity in entities:
                candidate = self._candidate_from_payload(entity, observation.get("source_kind", "observation"))
                if candidate is not None:
                    candidates.append(candidate)
        if not candidates:
            for entity in self._extract_entities(observation.get("facts", {}), "facts"):
                candidate = self._candidate_from_payload(entity, observation.get("source_kind", "observation"))
                if candidate is not None:
                    candidates.append(candidate)
        return candidates

    def _candidate_from_payload(self, entity: Dict[str, Any], source_kind: str) -> Optional[EntityCandidate]:
        if not isinstance(entity, dict):
            return None
        entity_type = str(entity.get("type") or "").strip().lower()
        entity_type = self._ENTITY_TYPE_ALIASES.get(entity_type, entity_type)
        raw_value = str(entity.get("value") or entity.get("label") or "").strip()
        if not entity_type or not raw_value:
            return None
        if entity_type not in self._CANONICAL_ENTITY_TYPES:
            return None
        canonical_value, attributes = self._canonicalize(entity_type, raw_value, entity.get("attributes", {}))
        if not canonical_value:
            return None
        normalized_attributes = dict(attributes)
        normalized_attributes.setdefault(
            "entity_family",
            self._ENTITY_TYPE_FAMILIES.get(entity_type, "generic"),
        )
        return EntityCandidate(
            type=entity_type,
            raw_value=raw_value,
            canonical_value=canonical_value,
            label=str(entity.get("label") or raw_value),
            source_kind=str(source_kind or entity.get("source_kind") or "observation"),
            source_path=str(entity.get("source_path") or "facts"),
            extraction_method=str(entity.get("extraction_method") or "normalizer"),
            confidence=float(entity.get("confidence", 0.6) or 0.6),
            attributes=normalized_attributes,
        )

    def _extract_entities(self, value: Any, source_path: str) -> Iterable[Dict[str, Any]]:
        if value is None:
            return []
        found: List[Dict[str, Any]] = []
        if isinstance(value, dict):
            for key, nested in value.items():
                found.extend(self._extract_entities(nested, f"{source_path}.{key}" if source_path else str(key)))
            return found
        if isinstance(value, list):
            for index, item in enumerate(value):
                found.extend(self._extract_entities(item, f"{source_path}[{index}]"))
            return found

        text = str(value).strip()
        if not text:
            return []
        lowered = source_path.lower()
        if any(token in lowered for token in ("sender", "from_address", "mail_from")):
            return [{"type": "sender", "value": text.lower() if "@" in text else text, "label": text, "source_path": source_path, "confidence": 0.84, "attributes": {"domain_role": "email_sender"}}]
        if any(token in lowered for token in ("recipient", "to_address", "rcpt_to", "delivered_to")):
            return [{"type": "recipient", "value": text.lower() if "@" in text else text, "label": text, "source_path": source_path, "confidence": 0.84, "attributes": {"domain_role": "email_recipient"}}]
        if any(token in lowered for token in ("user", "username", "account", "owner")):
            return [{"type": "user", "value": text, "label": text, "source_path": source_path, "confidence": 0.8, "attributes": {"domain_role": "identity_user"}}]
        if any(token in lowered for token in ("host", "hostname", "device", "computer")):
            return [{"type": "host", "value": text, "label": text, "source_path": source_path, "confidence": 0.82, "attributes": {"domain_role": "host_device"}}]
        if any(token in lowered for token in ("asset", "asset_id")):
            return [{"type": "asset", "value": text, "label": text, "source_path": source_path, "confidence": 0.8, "attributes": {"domain_role": "managed_asset"}}]
        if any(token in lowered for token in ("session", "logon_id", "login_id", "sid")):
            return [{"type": "session", "value": text, "label": text, "source_path": source_path, "confidence": 0.88, "attributes": {"domain_role": "auth_session"}}]
        if any(token in lowered for token in ("process", "image", "cmdline", "command_line")):
            return [{"type": "process", "value": text, "label": text, "source_path": source_path, "confidence": 0.72, "attributes": {"domain_role": "host_process"}}]
        if any(token in lowered for token in ("file", "file_name", "filename", "attachment", "path")) and not self._is_ip(text):
            return [{"type": "file", "value": text, "label": text, "source_path": source_path, "confidence": 0.74}]
        if any(token in lowered for token in ("alert", "alert_id", "alert_name", "detection")):
            return [{"type": "alert", "value": text, "label": text, "source_path": source_path, "confidence": 0.78}]
        if any(token in lowered for token in ("ip", "src_ip", "dest_ip", "client_ip", "remote_ip")) and self._is_ip(text):
            return [{"type": "ip", "value": text, "label": text, "source_path": source_path, "confidence": 0.92}]
        if self._EMAIL_RE.fullmatch(text):
            return [{"type": "email", "value": text.lower(), "label": text.lower(), "source_path": source_path, "confidence": 0.88}]
        if self._is_ip(text):
            return [{"type": "ip", "value": text, "label": text, "source_path": source_path, "confidence": 0.9}]
        if self._DOMAIN_RE.fullmatch(text.lower()):
            return [{"type": "domain", "value": text.lower(), "label": text.lower(), "source_path": source_path, "confidence": 0.8}]
        if self._HASH_RE.fullmatch(text):
            return [{"type": "hash", "value": text.lower(), "label": text.lower(), "source_path": source_path, "confidence": 0.85}]

        found.extend({"type": "ip", "value": item, "label": item, "source_path": source_path, "confidence": 0.74} for item in self._IP_RE.findall(text) if self._is_ip(item))
        found.extend({"type": "domain", "value": item.lower(), "label": item.lower(), "source_path": source_path, "confidence": 0.7} for item in self._DOMAIN_RE.findall(text))
        found.extend({"type": "email", "value": item.lower(), "label": item.lower(), "source_path": source_path, "confidence": 0.72} for item in self._EMAIL_RE.findall(text))
        return found

    def _canonicalize(self, entity_type: str, raw_value: str, attributes: Any) -> tuple[str, Dict[str, Any]]:
        attrs = dict(attributes or {})
        value = str(raw_value or "").strip()
        if entity_type == "ip":
            if not self._is_ip(value):
                return "", {}
            ip_obj = ipaddress.ip_address(value)
            attrs.update(
                {
                    "is_private": ip_obj.is_private,
                    "is_reserved": ip_obj.is_reserved,
                    "is_loopback": ip_obj.is_loopback,
                    "version": ip_obj.version,
                }
            )
            return value, attrs
        if entity_type in {"domain", "email", "hash", "sender", "recipient"}:
            return value.lower(), attrs
        if entity_type in {"process", "file"}:
            basename = os.path.basename(value) if os.path.sep in value else value
            if basename != value:
                attrs.setdefault("path", value)
            if entity_type == "process":
                attrs.setdefault("process_name", basename.lower())
            return basename, attrs
        if entity_type in {"host", "asset"}:
            attrs.setdefault("normalized_name", value.lower())
            return value.lower(), attrs
        if entity_type == "user":
            if "@" in value:
                attrs.setdefault("identity_kind", "email_principal")
                return value.lower(), attrs
            attrs.setdefault("identity_kind", "account_name")
            return value, attrs
        if entity_type == "session":
            attrs.setdefault("session_kind", "auth_session")
            return value, attrs
        return value, attrs

    def _upsert_entity(self, state: Dict[str, Any], candidate: EntityCandidate, evidence_ref: Dict[str, Any]) -> str:
        entity_id = f"{candidate.type}:{candidate.canonical_value}".lower()
        entities = state.setdefault("entities", {})
        record = entities.get(entity_id)
        if record is None:
            record = EntityRecord(
                id=entity_id,
                type=candidate.type,
                value=candidate.raw_value,
                canonical_value=candidate.canonical_value,
                label=candidate.label,
            ).to_dict()
            entities[entity_id] = record

        record["value"] = candidate.raw_value
        record["canonical_value"] = candidate.canonical_value
        record["label"] = candidate.label or record.get("label") or candidate.raw_value
        record["confidence"] = max(float(record.get("confidence", 0.0) or 0.0), float(candidate.confidence))
        record["last_seen_at"] = evidence_ref.get("created_at") or _now_iso()
        record["observation_count"] = int(record.get("observation_count", 0) or 0) + 1
        record["aliases"] = self._dedupe([*record.get("aliases", []), candidate.raw_value, candidate.label])
        record["source_paths"] = self._dedupe([*record.get("source_paths", []), candidate.source_path])[-12:]
        record["extraction_methods"] = self._dedupe([*record.get("extraction_methods", []), candidate.extraction_method])[-8:]
        merged_attributes = dict(record.get("attributes", {}))
        merged_attributes.update(candidate.attributes)
        record["attributes"] = merged_attributes
        domain_roles = self._dedupe(
            [
                *record.get("domain_roles", []),
                str(candidate.attributes.get("domain_role") or "").strip(),
            ]
        )
        if domain_roles:
            record["domain_roles"] = domain_roles
        refs = list(record.get("evidence_refs", []))
        refs.append(
            {
                "tool_name": evidence_ref.get("tool_name"),
                "step_number": evidence_ref.get("step_number"),
                "finding_index": evidence_ref.get("finding_index"),
                "summary": evidence_ref.get("summary"),
                "source_path": candidate.source_path,
                "extraction_method": candidate.extraction_method,
                "confidence": round(float(candidate.confidence), 3),
            }
        )
        record["evidence_refs"] = refs[-12:]
        return entity_id

    def _upsert_observation(self, state: Dict[str, Any], observation: Dict[str, Any]) -> None:
        observations = [item for item in state.get("observations", []) if item.get("id") != observation["id"]]
        observations.append(observation)
        observations.sort(key=lambda item: (item.get("step_number", 0), item.get("timestamp", "")))
        state["observations"] = observations[-50:]

    def _relations_from_observation(
        self,
        *,
        observation: Dict[str, Any],
        entity_ids_by_type: Dict[str, List[str]],
        evidence_ref: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        obs_type = str(observation.get("observation_type") or "").strip().lower()
        typed_fact = observation.get("typed_fact", {}) if isinstance(observation.get("typed_fact"), dict) else {}
        fact_family = str(observation.get("fact_family") or typed_fact.get("family") or "").strip().lower()
        typed_type = str(typed_fact.get("type") or "").strip().lower()
        effective_obs_type = obs_type
        if effective_obs_type in {"", "correlation_observation"}:
            if typed_type in {"network_event", "auth_event", "process_event", "file_execution", "email_delivery", "host_timeline_event", "vulnerability_exposure"}:
                effective_obs_type = typed_type
            elif fact_family == "network":
                effective_obs_type = "network_event"
        facts = observation.get("facts", {}) if isinstance(observation.get("facts"), dict) else {}
        source_paths = list(observation.get("source_paths", []))
        relations: List[Dict[str, Any]] = []

        def _first(kind: str) -> Optional[str]:
            items = entity_ids_by_type.get(kind, [])
            return items[0] if items else None

        def _add(source: Optional[str], target: Optional[str], relation: str, confidence: float, basis: str, explicit: bool = True) -> None:
            if not source or not target or source == target:
                return
            relation_strength = "explicit" if explicit else "inferred"
            guarded, guard_reason = self._sensitive_relation_guard(
                source=source,
                target=target,
                relation=relation,
                basis=basis,
                facts=facts,
                source_paths=source_paths,
                explicit=explicit,
            )
            if guarded == "skip":
                return
            adjusted_confidence = float(confidence)
            if guarded == "degrade":
                adjusted_confidence = min(adjusted_confidence, 0.69 if explicit else 0.58)
                relation_strength = "inferred"
                explicit = False
            relations.append(
                {
                    "source": source,
                    "target": target,
                    "relation": relation,
                    "confidence": round(float(adjusted_confidence), 3),
                    "basis": basis,
                    "relation_basis": basis,
                    "source_paths": source_paths,
                    "evidence_refs": [
                        self._relation_ref(
                            evidence_ref,
                            observation.get("observation_id"),
                            source_paths=source_paths,
                            extraction_method=str(observation.get("extraction_method") or "normalizer"),
                            relation_strength=relation_strength,
                        )
                    ],
                    "explicit": explicit,
                    "inferred": not explicit,
                    "relation_strength": relation_strength,
                    "canonical_source": source,
                    "canonical_target": target,
                    "guarded": guarded != "allow",
                    "guard_reason": guard_reason,
                    "count": 1,
                    "last_seen_at": evidence_ref.get("created_at") or _now_iso(),
                }
            )

        user_id = _first("user")
        session_id = _first("session")
        host_id = _first("host")
        process_id = _first("process")
        file_id = _first("file")
        asset_id = _first("asset")
        alert_id = _first("alert")
        sender_id = _first("sender") or _first("email")
        recipient_id = _first("recipient") or user_id
        source_ip_id = self._entity_by_value(entity_ids_by_type.get("ip", []), facts.get("source_ip"))
        dest_ip_id = self._entity_by_value(entity_ids_by_type.get("ip", []), facts.get("dest_ip"))
        domain_id = self._entity_by_value(entity_ids_by_type.get("domain", []), facts.get("domain"))
        url_id = _first("url")

        if effective_obs_type == "auth_event":
            _add(session_id, user_id, "belongs_to", 0.94, "auth_event:user_session")
            _add(session_id, host_id or asset_id, "occurred_on", 0.93, "auth_event:host")
            _add(session_id, source_ip_id, "authenticated_from", 0.95, "auth_event:source_ip")
            _add(user_id, source_ip_id, "authenticated_from", 0.82, "auth_event:user_source_ip", explicit=False)
        elif effective_obs_type in {"process_event", "file_execution"}:
            _add(process_id, host_id or asset_id, "executed_on", 0.92, "process_event:host")
            _add(process_id, session_id, "derived_from", 0.78, "process_event:session", explicit=False)
            _add(process_id, dest_ip_id, "connects_to", 0.84, "process_event:dest_ip")
            _add(process_id, domain_id or url_id, "connects_to", 0.8, "process_event:network")
            _add(file_id, process_id, "spawned_process", 0.83, "file_execution:process")
        elif effective_obs_type == "network_event":
            source_actor = process_id or user_id or host_id or session_id
            _add(source_actor, dest_ip_id, "connects_to", 0.88, "network_event:dest_ip")
            _add(source_actor, domain_id or url_id, "connects_to", 0.84, "network_event:destination")
            _add(session_id, host_id or asset_id, "occurred_on", 0.8, "network_event:host")
        elif effective_obs_type == "email_delivery":
            _add(recipient_id, sender_id, "received_from", 0.84, "email_delivery:sender_recipient")
            _add(recipient_id, file_id, "received_attachment", 0.81, "email_delivery:attachment", explicit=False)
            _add(sender_id, domain_id, "originates_from", 0.76, "email_delivery:sender_domain", explicit=False)
        elif effective_obs_type == "host_timeline_event":
            _add(session_id, host_id or asset_id, "occurred_on", 0.76, "host_timeline:session_host")
            _add(process_id, host_id or asset_id, "executed_on", 0.76, "host_timeline:process_host")
        elif effective_obs_type == "vulnerability_exposure":
            _add(asset_id or host_id, alert_id, "exposed_by", 0.82, "vulnerability_exposure:alert", explicit=False)

        return relations

    def _co_observed_relations(
        self,
        *,
        entity_ids: List[str],
        source_paths: List[str],
        evidence_ref: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        relations: List[Dict[str, Any]] = []
        for index, source in enumerate(entity_ids):
            for target in entity_ids[index + 1:]:
                if self._is_sensitive_pair(source, target):
                    continue
                relations.append(
                    {
                        "source": source,
                        "target": target,
                        "relation": "co_observed",
                        "confidence": 0.28 if self._is_high_risk_pair(source, target) else 0.4,
                        "basis": "shared_observation_context",
                        "relation_basis": "shared_observation_context",
                        "source_paths": list(source_paths),
                        "evidence_refs": [
                            self._relation_ref(
                                evidence_ref,
                                None,
                                source_paths=list(source_paths),
                                extraction_method="co_observed",
                                relation_strength="co_observed",
                            )
                        ],
                        "explicit": False,
                        "inferred": False,
                        "relation_strength": "co_observed",
                        "canonical_source": source,
                        "canonical_target": target,
                        "guarded": self._is_high_risk_pair(source, target),
                        "guard_reason": "high_risk_pair_requires_stronger_evidence" if self._is_high_risk_pair(source, target) else None,
                        "count": 1,
                        "last_seen_at": evidence_ref.get("created_at") or _now_iso(),
                    }
                )
        return relations

    def _upsert_relationship(self, state: Dict[str, Any], relationship: Dict[str, Any]) -> None:
        relationships = {
            self._relationship_key(item): item
            for item in state.get("relationships", [])
            if isinstance(item, dict)
        }
        key = self._relationship_key(relationship)
        current = dict(relationships.get(key, {}))
        merged = {**current, **relationship}
        merged["confidence"] = max(float(current.get("confidence", 0.0) or 0.0), float(relationship.get("confidence", 0.0) or 0.0))
        merged["count"] = int(current.get("count", 0) or 0) + 1
        merged["source_paths"] = self._dedupe([*current.get("source_paths", []), *relationship.get("source_paths", [])])[-12:]
        merged_refs = [*current.get("evidence_refs", []), *relationship.get("evidence_refs", [])]
        deduped_refs: List[Dict[str, Any]] = []
        seen_ref_keys = set()
        for ref in merged_refs:
            if not isinstance(ref, dict):
                continue
            ref_key = (
                str(ref.get("observation_id") or ""),
                str(ref.get("tool_name") or ""),
                str(ref.get("step_number") or ""),
                str(ref.get("finding_index") or ""),
                str(ref.get("summary") or ""),
            )
            if ref_key in seen_ref_keys:
                continue
            seen_ref_keys.add(ref_key)
            deduped_refs.append(ref)
        merged["evidence_refs"] = deduped_refs[-12:]
        merged["relation_basis"] = relationship.get("relation_basis") or relationship.get("basis") or current.get("relation_basis") or current.get("basis")
        merged["canonical_source"] = relationship.get("canonical_source") or current.get("canonical_source") or relationship.get("source")
        merged["canonical_target"] = relationship.get("canonical_target") or current.get("canonical_target") or relationship.get("target")
        merged["guarded"] = bool(current.get("guarded", False) or relationship.get("guarded", False))
        merged["guard_reason"] = relationship.get("guard_reason") or current.get("guard_reason")
        if merged.get("relation_strength") != "co_observed":
            merged["explicit"] = bool(current.get("explicit", False) or relationship.get("explicit", False))
            merged["inferred"] = not bool(merged.get("explicit"))
            merged["relation_strength"] = "explicit" if merged["explicit"] else "inferred"

        strength_breakdown = dict(current.get("strength_breakdown", {}))
        for ref in deduped_refs:
            if not isinstance(ref, dict):
                continue
            strength = str(ref.get("relation_strength") or merged.get("relation_strength") or "unknown").strip().lower()
            if not strength:
                continue
            strength_breakdown[strength] = strength_breakdown.get(strength, 0) + 1

        supporting_observations = {
            str(ref.get("observation_id") or "").strip().lower()
            for ref in deduped_refs
            if isinstance(ref, dict) and str(ref.get("observation_id") or "").strip()
        }
        merged["supporting_observation_count"] = len(supporting_observations)
        merged["evidence_count"] = len(deduped_refs)
        merged["source_path_count"] = len(merged.get("source_paths", []))
        merged["strength_breakdown"] = strength_breakdown
        merged["relation_semantics"] = {
            "is_explicit": bool(merged.get("explicit", False)),
            "is_inferred": bool(merged.get("inferred", False)),
            "is_co_observed": str(merged.get("relation_strength") or "") == "co_observed",
            "strength": merged.get("relation_strength"),
            "supporting_observation_count": len(supporting_observations),
            "evidence_count": len(deduped_refs),
            "guarded": bool(merged.get("guarded", False)),
        }
        relationships[key] = merged
        state["relationships"] = list(relationships.values())[-120:]

    @staticmethod
    def _relationship_key(relationship: Dict[str, Any]) -> str:
        return "|".join(
            [
                str(relationship.get("source") or ""),
                str(relationship.get("target") or ""),
                str(relationship.get("relation") or ""),
                str(relationship.get("basis") or ""),
            ]
        )

    @staticmethod
    def _entity_type(entity_id: Optional[str]) -> str:
        return str(entity_id or "").split(":", 1)[0].strip().lower()

    def _is_sensitive_pair(self, source: Optional[str], target: Optional[str]) -> bool:
        pair = {self._entity_type(source), self._entity_type(target)}
        return pair in (
            {"user", "session"},
            {"host", "process"},
            {"asset", "process"},
            {"process", "ip"},
            {"process", "domain"},
            {"process", "url"},
            {"sender", "recipient"},
            {"email", "recipient"},
            {"email", "user"},
        )

    def _is_high_risk_pair(self, source: Optional[str], target: Optional[str]) -> bool:
        pair = {self._entity_type(source), self._entity_type(target)}
        return pair in (
            {"user", "host"},
            {"user", "process"},
            {"session", "ip"},
            {"host", "ip"},
        )

    def _sensitive_relation_guard(
        self,
        *,
        source: Optional[str],
        target: Optional[str],
        relation: str,
        basis: str,
        facts: Dict[str, Any],
        source_paths: List[str],
        explicit: bool,
    ) -> tuple[str, Optional[str]]:
        source_type = self._entity_type(source)
        target_type = self._entity_type(target)
        pair = {source_type, target_type}
        lowered_paths = " ".join(str(item).lower() for item in source_paths)
        if pair == {"user", "session"} and not (facts.get("session_id") and (facts.get("user") or facts.get("username") or facts.get("account"))):
            return ("degrade", "user_session_link_missing_direct_fact_pair")
        if pair in ({"host", "process"}, {"asset", "process"}) and not (facts.get("process_name") and (facts.get("host") or facts.get("hostname") or facts.get("device"))):
            return ("degrade", "process_host_link_missing_direct_fact_pair")
        if pair in ({"process", "ip"}, {"process", "domain"}, {"process", "url"}) and not (
            facts.get("dest_ip") or facts.get("domain") or facts.get("url") or "network" in lowered_paths
        ):
            return ("degrade", "process_network_link_missing_destination_evidence")
        if pair in ({"sender", "recipient"}, {"email", "recipient"}, {"email", "user"}) and not (
            any(key in facts for key in ("sender", "sender_address", "from_address", "recipient", "to_address", "delivered_to"))
            or "mail" in lowered_paths
            or "email" in lowered_paths
        ):
            return ("skip", "email_identity_link_missing_delivery_evidence")
        if not explicit and self._is_sensitive_pair(source, target):
            return ("degrade", f"sensitive_relation_inferred_only:{relation}:{basis}")
        return ("allow", None)

    @staticmethod
    def _relation_ref(
        evidence_ref: Dict[str, Any],
        observation_id: Optional[str],
        *,
        source_paths: Optional[List[str]] = None,
        extraction_method: Optional[str] = None,
        relation_strength: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "observation_id": observation_id,
            "tool_name": evidence_ref.get("tool_name"),
            "step_number": evidence_ref.get("step_number"),
            "finding_index": evidence_ref.get("finding_index"),
            "summary": evidence_ref.get("summary"),
            "source_paths": list(source_paths or []),
            "source_path": list(source_paths or [None])[0],
            "extraction_method": extraction_method,
            "relation_strength": relation_strength,
        }

    @staticmethod
    def _entity_by_value(entity_ids: List[str], value: Optional[str]) -> Optional[str]:
        if not value:
            return entity_ids[0] if entity_ids else None
        target = str(value).strip().lower()
        for entity_id in entity_ids:
            if entity_id.lower().endswith(f":{target}"):
                return entity_id
        return entity_ids[0] if entity_ids else None

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            clean = str(value or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(clean)
        return ordered

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False


def evidence_ref_timestamp(result: Any) -> str:
    if isinstance(result, dict):
        return str(result.get("timestamp") or result.get("@timestamp") or result.get("_time") or _now_iso())
    return _now_iso()
