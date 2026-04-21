"""Explicit log-hunt planning for investigator-driven telemetry pivots."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..utils.log_hunting_policy import normalize_query_bundle, parse_timerange


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LogQueryPlan:
    lane: str
    focus: str
    timerange: str
    max_results: int
    query_bundle: Dict[str, List[str]]
    pivot_sequence: List[str]
    next_entities: List[str]
    reasoning: str
    generated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LogQueryPlanner:
    """Turn investigation context into explicit log-hunt pivots and query bundles."""

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _SESSION_HINT_RE = re.compile(r"\b(?:session|logon|sid|token)[-_:\s]*([a-zA-Z0-9._:-]{3,})\b", re.IGNORECASE)

    def build_plan(
        self,
        *,
        query: Any = None,
        focus: str = "",
        analyst_request: str = "",
        lane: str = "",
        unresolved_questions: Optional[List[str]] = None,
        entity_state: Optional[Dict[str, Any]] = None,
        timerange: str = "24h",
        max_results: int = 200,
    ) -> Dict[str, Any]:
        normalized_existing = normalize_query_bundle(query)
        clean_lane = str(lane or "").strip().lower()
        clean_focus = str(focus or "").strip()
        if not clean_focus:
            clean_focus = self._focus_from_request(analyst_request, entity_state)

        questions = [
            str(item).strip()
            for item in (unresolved_questions or [])
            if str(item).strip()
        ]
        pivot_sequence = self._pivot_sequence(clean_lane, clean_focus, questions)
        next_entities = self._next_entities(clean_lane, clean_focus, questions)

        if normalized_existing:
            query_bundle = normalized_existing
            reasoning = "Reused caller-provided hunt queries and attached explicit pivot metadata."
        else:
            query_bundle = self._build_query_bundle(clean_lane, clean_focus, questions, next_entities, max_results)
            reasoning = "Built focused log-hunt pivots from the current investigation lane, focus entity, and unresolved questions."

        _, _, _, normalized_timerange = parse_timerange(timerange or "24h", default="24h")
        return LogQueryPlan(
            lane=clean_lane or "generic",
            focus=clean_focus,
            timerange=normalized_timerange,
            max_results=max_results,
            query_bundle=query_bundle,
            pivot_sequence=pivot_sequence,
            next_entities=next_entities,
            reasoning=reasoning,
        ).to_dict()

    def _focus_from_request(self, analyst_request: str, entity_state: Optional[Dict[str, Any]]) -> str:
        text = str(analyst_request or "").strip()
        for pattern in (self._IP_RE, self._EMAIL_RE, self._DOMAIN_RE):
            match = pattern.search(text)
            if match:
                return match.group(0)
        session_match = self._SESSION_HINT_RE.search(text)
        if session_match:
            return session_match.group(1)

        entities = entity_state.get("entities", {}) if isinstance(entity_state, dict) else {}
        for preferred_type in ("session", "user", "host", "process", "ip", "domain", "url"):
            for entity in entities.values() if isinstance(entities, dict) else []:
                if not isinstance(entity, dict):
                    continue
                if str(entity.get("type") or "").strip().lower() != preferred_type:
                    continue
                value = str(entity.get("value") or entity.get("label") or "").strip()
                if value:
                    return value
        return text[:160]

    def _pivot_sequence(self, lane: str, focus: str, questions: List[str]) -> List[str]:
        focus_kind = self._focus_kind(focus)
        if lane == "log_identity":
            base = ["user", "session", "host", "process"]
            if any(token in " ".join(questions).lower() for token in ("outbound", "egress", "fortigate", "beacon", "callback", "destination")):
                base = ["network", "host", "user", "session", "process"]
            elif any(token in " ".join(questions).lower() for token in ("4624", "4625", "winlogon", "logon type", "failed", "success")):
                base = ["user", "host", "session", "network", "process"]
        elif focus_kind == "ip":
            base = ["ip", "session", "user", "host"]
        elif focus_kind == "user":
            base = ["user", "session", "host", "process"]
        elif focus_kind == "host":
            base = ["host", "process", "network", "session"]
        elif focus_kind == "session":
            base = ["session", "user", "host", "process"]
        elif focus_kind == "process":
            base = ["process", "host", "network", "user"]
        else:
            base = ["host", "user", "session", "network"]

        hinted = []
        merged_text = " ".join(questions).lower()
        if any(token in merged_text for token in ("identity", "user", "account")):
            hinted.append("user")
        if any(token in merged_text for token in ("session", "token", "logon")):
            hinted.append("session")
        if any(token in merged_text for token in ("host", "endpoint", "device")):
            hinted.append("host")
        if any(token in merged_text for token in ("process", "execution", "binary", "command line")):
            hinted.append("process")
        if any(token in merged_text for token in ("network", "beacon", "connection", "destination")):
            hinted.append("network")

        ordered: List[str] = []
        for item in [*hinted, *base]:
            if item not in ordered:
                ordered.append(item)
        return ordered[:5]

    def _next_entities(self, lane: str, focus: str, questions: List[str]) -> List[str]:
        next_entities = list(self._pivot_sequence(lane, focus, questions))
        focus_kind = self._focus_kind(focus)
        if focus_kind and focus_kind not in next_entities:
            next_entities.insert(0, focus_kind)
        return next_entities[:5]

    def _build_query_bundle(
        self,
        lane: str,
        focus: str,
        questions: List[str],
        next_entities: List[str],
        max_results: int,
    ) -> Dict[str, List[str]]:
        focus_kind = self._focus_kind(focus)
        safe_focus = str(focus or "").replace('"', '\\"')
        spl_queries: List[str] = []

        if focus_kind == "ip":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR src_ip="{safe_focus}" OR dest_ip="{safe_focus}" OR source_ip="{safe_focus}" OR remote_ip="{safe_focus}")'
                f" | head {max_results}"
            )
        elif focus_kind == "email":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR user="{safe_focus}" OR account="{safe_focus}" OR recipient="{safe_focus}" OR sender="{safe_focus}")'
                f" | head {max_results}"
            )
        elif focus_kind == "domain":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR domain="{safe_focus}" OR query="{safe_focus}" OR url="*{safe_focus}*")'
                f" | head {max_results}"
            )
        elif focus_kind == "session":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR session_id="{safe_focus}" OR logon_id="{safe_focus}" OR session="{safe_focus}")'
                f" | head {max_results}"
            )
        elif focus_kind == "user":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR user="{safe_focus}" OR username="{safe_focus}" OR account="{safe_focus}")'
                f" | head {max_results}"
            )
        elif focus_kind == "host":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR host="{safe_focus}" OR hostname="{safe_focus}" OR device="{safe_focus}")'
                f" | head {max_results}"
            )
        elif focus_kind == "process":
            spl_queries.append(
                f'search index=* ("{safe_focus}" OR process_name="{safe_focus}" OR image="{safe_focus}" OR process="{safe_focus}")'
                f" | head {max_results}"
            )
        else:
            summary = focus or "suspicious activity"
            spl_queries.append(f'search index=* "{summary}" | head {max_results}')

        question_text = " ".join(questions).lower()
        if lane == "log_identity" or any(item in next_entities for item in ("user", "session")):
            spl_queries.append(
                "search index=* (action=login OR action=logon OR event_name=authentication OR EventCode=4624 OR EventCode=4625)"
                " | head 200"
            )
        if any(token in question_text for token in ("fortigate", "outbound", "egress", "firewall", "beacon", "callback", "destination", "dest_ip")):
            spl_queries.append(
                "search index=* (device_vendor=Fortinet OR sourcetype=*fortigate* OR firewall*) "
                "(dest_ip=* OR destination_ip=* OR remote_ip=* OR service=* OR action=* OR policyid=*) | head 200"
            )
        if any(token in question_text for token in ("4624", "4625", "winlogon", "windows logon", "logon type", "failed", "success")):
            spl_queries.append(
                "search index=* (EventCode=4624 OR EventCode=4625 OR event_id=4624 OR event_id=4625 OR Logon_Type=* OR logon_type=*) | head 200"
            )
        if any(item in next_entities for item in ("process", "host")):
            spl_queries.append(
                "search index=* (process_name=* OR image=* OR command_line=* OR cmdline=*) | head 200"
            )

        generic = [
            f"Investigate telemetry around {focus or 'the current investigation focus'} and pivot through {', '.join(next_entities[:4])}."
        ]
        if questions:
            generic.append("Prioritize these questions: " + "; ".join(questions[:3]))

        return {
            "splunk": spl_queries[:3],
            "generic": generic[:2],
        }

    def _focus_kind(self, focus: str) -> str:
        text = str(focus or "").strip()
        lowered = text.lower()
        if not text:
            return ""
        if self._IP_RE.fullmatch(text):
            return "ip"
        if self._EMAIL_RE.fullmatch(text):
            return "email"
        if lowered.startswith(("http://", "https://")):
            return "url"
        if self._DOMAIN_RE.fullmatch(lowered):
            return "domain"
        if any(token in lowered for token in ("logon", "session", "token", "sid-")):
            return "session"
        if any(sep in text for sep in ("\\", "/")) or lowered.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".sh")):
            return "process"
        if "@" not in text and any(token in lowered for token in ("ws-", "srv-", "host-", "endpoint", "device")):
            return "host"
        if any(token in lowered for token in ("alice", "bob", "svc_", "user", "admin")):
            return "user"
        return ""
