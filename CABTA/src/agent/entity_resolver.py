"""Lightweight entity normalization for investigation sessions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EntityRecord:
    id: str
    type: str
    value: str
    label: str
    aliases: List[str] = field(default_factory=list)
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    first_seen_at: str = field(default_factory=_now_iso)
    last_seen_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "label": self.label,
            "aliases": list(self.aliases),
            "evidence_refs": list(self.evidence_refs),
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
        }


class EntityResolver:
    """Thin session-level entity resolver.

    It does not attempt global identity resolution. It only normalizes entities
    observed during one investigation session and links those co-observations.
    """

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
    _HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    _CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    _SESSION_KEYWORDS = ("session", "session_id", "logon_id", "login_id", "auth_session", "sid")
    _USER_KEYWORDS = ("user", "username", "account", "principal", "email", "upn", "owner")
    _HOST_KEYWORDS = ("host", "hostname", "device", "computer", "workstation", "endpoint")
    _PROCESS_KEYWORDS = ("process", "process_name", "image", "image_path", "command", "cmdline", "executable")
    _IP_KEYWORDS = ("ip", "src_ip", "dest_ip", "remote_ip", "destination_ip", "source_ip")

    def bootstrap(self, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        state = dict(existing or {})
        state.setdefault("schema_version", 1)
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
    ) -> Dict[str, Any]:
        state = self.bootstrap(entity_state)
        entities = {
            entity["id"]: entity
            for entity in self._collect_entities(params, result)
        }

        for entity in entities.values():
            self._upsert_entity(state, entity, evidence_ref)

        entity_ids = list(entities.keys())
        if entity_ids:
            self._upsert_observation(
                state,
                {
                    "id": f"obs:{session_id}:{step_number}:{tool_name}".lower(),
                    "step_number": step_number,
                    "tool_name": tool_name,
                    "summary": evidence_ref.get("summary", ""),
                    "entity_ids": entity_ids,
                    "timestamp": evidence_ref.get("created_at") or _now_iso(),
                },
            )
            self._link_entities(state, entities, evidence_ref)

        state["updated_at"] = _now_iso()
        return state

    def summarize_for_case_event(self, entity_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        state = self.bootstrap(entity_state)
        entities = list(state.get("entities", {}).values())
        relationships = list(state.get("relationships", []))
        summary = {
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "entities": entities[:20],
            "relationships": relationships[:30],
        }
        return summary

    def _collect_entities(self, params: Dict[str, Any], result: Any) -> List[Dict[str, Any]]:
        entities: Dict[str, Dict[str, Any]] = {}
        payloads = [
            ("params", params),
            ("result", result.get("result") if isinstance(result, dict) and isinstance(result.get("result"), dict) else result),
        ]
        for source_name, payload in payloads:
            for kind, value, label in self._extract_from_value(payload):
                entity_id = f"{kind}:{value}".lower()
                entities.setdefault(
                    entity_id,
                    {
                        "id": entity_id,
                        "type": kind,
                        "value": value,
                        "label": label,
                        "source": source_name,
                    },
                )
        return list(entities.values())

    def _extract_from_value(self, value: Any, key_hint: str = "") -> Iterable[Tuple[str, str, str]]:
        if value is None:
            return []

        found: List[Tuple[str, str, str]] = []
        if isinstance(value, dict):
            for key, nested in value.items():
                found.extend(self._extract_from_value(nested, key_hint=str(key)))
            return found

        if isinstance(value, list):
            for item in value:
                found.extend(self._extract_from_value(item, key_hint=key_hint))
            return found

        text = str(value).strip()
        if not text:
            return []

        hinted = self._entities_from_key_hint(key_hint, text)
        if hinted:
            return hinted

        if self._URL_RE.fullmatch(text):
            return [("url", text, text)]
        if self._EMAIL_RE.fullmatch(text):
            return [("user", text.lower(), text.lower()), ("email", text.lower(), text.lower())]
        if self._IP_RE.fullmatch(text):
            return [("ip", text, text)]
        if self._DOMAIN_RE.fullmatch(text):
            return [("domain", text.lower(), text.lower())]
        if self._HASH_RE.fullmatch(text):
            return [("hash", text.lower(), text.lower())]
        if self._CVE_RE.fullmatch(text):
            return [("cve", text.upper(), text.upper())]
        if text.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".js")):
            return [("process", text, text)]

        found.extend(("ip", ip, ip) for ip in self._IP_RE.findall(text))
        found.extend(("url", url, url) for url in self._URL_RE.findall(text))
        found.extend(("email", email.lower(), email.lower()) for email in self._EMAIL_RE.findall(text))
        found.extend(("domain", domain.lower(), domain.lower()) for domain in self._DOMAIN_RE.findall(text))
        found.extend(("cve", cve.upper(), cve.upper()) for cve in self._CVE_RE.findall(text))
        found.extend(("hash", hash_value.lower(), hash_value.lower()) for hash_value in self._HASH_RE.findall(text))
        return found

    def _entities_from_key_hint(self, key_hint: str, text: str) -> List[Tuple[str, str, str]]:
        normalized_key = str(key_hint or "").strip().lower()
        if not normalized_key:
            return []

        if any(token in normalized_key for token in self._SESSION_KEYWORDS):
            return [("session", text, text)]
        if any(token in normalized_key for token in self._USER_KEYWORDS):
            email_match = self._EMAIL_RE.fullmatch(text)
            if email_match:
                return [("user", text.lower(), text.lower()), ("email", text.lower(), text.lower())]
            return [("user", text, text)]
        if any(token in normalized_key for token in self._HOST_KEYWORDS):
            return [("host", text, text)]
        if any(token in normalized_key for token in self._PROCESS_KEYWORDS):
            return [("process", text, text)]
        if any(token in normalized_key for token in self._IP_KEYWORDS):
            if self._IP_RE.fullmatch(text):
                return [("ip", text, text)]
        if "domain" in normalized_key:
            return [("domain", text.lower(), text.lower())]
        if "url" in normalized_key:
            return [("url", text, text)]
        if "hash" in normalized_key or normalized_key in {"sha256", "sha1", "md5"}:
            return [("hash", text.lower(), text.lower())]
        if "cve" in normalized_key:
            return [("cve", text.upper(), text.upper())]
        return []

    def _upsert_entity(self, state: Dict[str, Any], entity: Dict[str, Any], evidence_ref: Dict[str, Any]) -> None:
        entities = state.setdefault("entities", {})
        record = entities.get(entity["id"])
        if record is None:
            record = EntityRecord(
                id=entity["id"],
                type=entity["type"],
                value=entity["value"],
                label=entity["label"],
                aliases=[],
                evidence_refs=[],
            ).to_dict()
            entities[entity["id"]] = record

        record["last_seen_at"] = evidence_ref.get("created_at") or _now_iso()
        refs = list(record.get("evidence_refs", []))
        refs.append(
            {
                "tool_name": evidence_ref.get("tool_name"),
                "step_number": evidence_ref.get("step_number"),
                "finding_index": evidence_ref.get("finding_index"),
                "summary": evidence_ref.get("summary"),
            }
        )
        record["evidence_refs"] = refs[-10:]

    def _upsert_observation(self, state: Dict[str, Any], observation: Dict[str, Any]) -> None:
        observations = [item for item in state.get("observations", []) if item.get("id") != observation["id"]]
        observations.append(observation)
        observations.sort(key=lambda item: (item.get("step_number", 0), item.get("timestamp", "")))
        state["observations"] = observations[-25:]

    def _link_entities(self, state: Dict[str, Any], entities: Dict[str, Dict[str, Any]], evidence_ref: Dict[str, Any]) -> None:
        relationships = {self._relationship_key(item): item for item in state.get("relationships", [])}
        items = list(entities.values())
        for index, source in enumerate(items):
            for target in items[index + 1:]:
                relation = self._infer_relationship(source, target)
                relationship = {
                    "source": source["id"],
                    "target": target["id"],
                    "relation": relation,
                    "count": relationships.get(f"{source['id']}|{target['id']}|{relation}", {}).get("count", 0) + 1,
                    "last_seen_at": evidence_ref.get("created_at") or _now_iso(),
                    "evidence_ref": {
                        "tool_name": evidence_ref.get("tool_name"),
                        "step_number": evidence_ref.get("step_number"),
                        "summary": evidence_ref.get("summary"),
                    },
                }
                relationships[self._relationship_key(relationship)] = relationship
        state["relationships"] = list(relationships.values())[-60:]

    @staticmethod
    def _relationship_key(relationship: Dict[str, Any]) -> str:
        return f"{relationship.get('source')}|{relationship.get('target')}|{relationship.get('relation')}"

    @staticmethod
    def _infer_relationship(source: Dict[str, Any], target: Dict[str, Any]) -> str:
        pair = {source.get("type"), target.get("type")}
        if pair == {"user", "ip"}:
            return "associated_with"
        if pair == {"user", "host"}:
            return "uses_host"
        if pair == {"session", "host"}:
            return "occurred_on"
        if pair == {"session", "user"}:
            return "belongs_to"
        if pair == {"process", "host"}:
            return "executed_on"
        if pair == {"process", "session"}:
            return "follows_session"
        if pair == {"process", "ip"}:
            return "connects_to"
        return "linked_to"
