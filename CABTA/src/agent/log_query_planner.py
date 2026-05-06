"""Explicit log-hunt planning for investigator-driven telemetry pivots."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..utils.log_hunting_policy import normalize_query_bundle, parse_timerange
from .log_query_coverage import build_initial_coverage_matrix, build_query_fingerprint, infer_facets_from_text


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
    required_facets: List[str] = field(default_factory=list)
    query_variants: List[Dict[str, Any]] = field(default_factory=list)
    coverage_matrix: Dict[str, Any] = field(default_factory=dict)
    unresolved_questions: List[str] = field(default_factory=list)
    validation: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LogQueryPlanner:
    """Turn investigation context into explicit log-hunt pivots and query bundles."""

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _SESSION_HINT_RE = re.compile(r"\b(?:session|logon|sid|token)[-_:\s]*([a-zA-Z0-9._:-]{3,})\b", re.IGNORECASE)
    _FORTIGATE_KV_RE = re.compile(r'(\w+)=((?:"[^"]*")|\S+)')
    _FORTIGATE_FIELDS = {
        "date", "time", "devname", "devid", "srcip", "dstip", "srcport", "dstport",
        "service", "sessionid", "action", "type", "subtype", "srccountry", "dstcountry",
        "crlevel", "crscore",
    }

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
        fortigate_event = self._extract_fortigate_event(analyst_request)
        sysmon_event = self._extract_sysmon_event(analyst_request)
        wmi_alert = self._extract_wmi_alert(analyst_request)
        clean_focus = str(focus or "").strip()
        if clean_focus and self._is_bad_focus_candidate(clean_focus):
            clean_focus = ""
        if not clean_focus:
            clean_focus = self._focus_from_request(analyst_request, entity_state, fortigate_event=fortigate_event)
        if not clean_focus and wmi_alert.get("host"):
            clean_focus = str(wmi_alert.get("host"))

        questions = [
            str(item).strip()
            for item in (unresolved_questions or [])
            if str(item).strip()
        ]
        if wmi_alert:
            clean_lane = "host_process_log_hunt"
        pivot_sequence = self._pivot_sequence(clean_lane, clean_focus, questions)
        next_entities = self._next_entities(clean_lane, clean_focus, questions)
        required_facets = self._required_facets(clean_lane, clean_focus, questions, next_entities)
        entity_targets = self._entity_targets(clean_focus, entity_state, next_entities)

        if normalized_existing:
            query_bundle = normalized_existing
            query_variants = self._variants_from_bundle(query_bundle, required_facets)
            reasoning = "Reused caller-provided hunt queries and attached explicit pivot metadata."
        else:
            if wmi_alert:
                query_bundle = self._build_wmi_alert_query_bundle(wmi_alert, max_results)
            elif sysmon_event:
                query_bundle = self._build_sysmon_query_bundle(sysmon_event, max_results)
            else:
                query_bundle = self._build_query_bundle(clean_lane, clean_focus, questions, next_entities, max_results, fortigate_event=fortigate_event)
            query_variants = self._build_query_variants(query_bundle, required_facets, next_entities)
            reasoning = "Built focused log-hunt pivots from the current investigation lane, focus entity, and unresolved questions."
            if fortigate_event:
                reasoning = "Built bounded FortiGate SPL from deterministic key-value extraction and historical event time."
            if sysmon_event:
                reasoning = "Built bounded Sysmon SPL from deterministic event fields and concrete process pivots."
            if wmi_alert:
                reasoning = "Built bounded Splunk process-log pivots from deterministic WMI alert fields."

        validation = self._validation_metadata(query_bundle, query_variants, required_facets, max_results)
        coverage_matrix = build_initial_coverage_matrix(
            required_facets=required_facets,
            questions=questions,
            entity_targets=entity_targets,
        )

        if wmi_alert.get("timerange"):
            normalized_timerange = str(wmi_alert["timerange"])
        elif sysmon_event.get("timerange"):
            normalized_timerange = str(sysmon_event["timerange"])
        elif fortigate_event.get("timerange"):
            normalized_timerange = str(fortigate_event["timerange"])
        else:
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
            required_facets=required_facets,
            query_variants=query_variants,
            coverage_matrix=coverage_matrix,
            unresolved_questions=questions,
            validation=validation,
        ).to_dict()

    def _focus_from_request(self, analyst_request: str, entity_state: Optional[Dict[str, Any]], *, fortigate_event: Optional[Dict[str, str]] = None) -> str:
        text = str(analyst_request or "").strip()
        if fortigate_event:
            for key in ("srcip", "dstip", "sessionid", "devname", "devid"):
                value = str(fortigate_event.get(key) or "").strip()
                if value:
                    return value
        for pattern in (self._IP_RE, self._EMAIL_RE, self._DOMAIN_RE):
            match = pattern.search(text)
            if match:
                candidate = match.group(0)
                if not self._is_bad_focus_candidate(candidate):
                    return candidate
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
        *,
        fortigate_event: Optional[Dict[str, str]] = None,
    ) -> Dict[str, List[str]]:
        if fortigate_event:
            return self._build_fortigate_query_bundle(fortigate_event, max_results)

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

    def _required_facets(self, lane: str, focus: str, questions: List[str], next_entities: List[str]) -> List[str]:
        facets: List[str] = []
        question_text = " ".join(questions).lower()
        if lane == "log_identity":
            facets.extend(["user", "host", "session"])
        if lane == "host_process_log_hunt" or any(token in question_text for token in ("wmi", "get-wmiobject", "command line", "event id", "sysmon", "powershell")):
            facets.extend(["timestamp", "host", "process", "command_line", "event_code", "user", "source_sourcetype", "backend", "raw_event"])
        focus_kind = self._focus_kind(focus)
        if focus_kind in {"user", "host", "session", "process"}:
            facets.append(focus_kind)
        if focus_kind in {"ip", "domain", "url"}:
            facets.append("network")
        for question in questions:
            facets.extend(infer_facets_from_text(question))
        for entity in next_entities:
            if entity in {"user", "host", "session", "process", "network"}:
                facets.append(entity)
        deduped = list(dict.fromkeys(facets or ["network"]))
        if lane == "host_process_log_hunt" or any(token in question_text for token in ("wmi", "get-wmiobject", "command line", "event id", "sysmon", "powershell")):
            return deduped
        return deduped[:6]

    def _entity_targets(self, focus: str, entity_state: Optional[Dict[str, Any]], next_entities: List[str]) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        focus_kind = self._focus_kind(focus)
        if focus and focus_kind:
            targets.append({"value": focus, "type": focus_kind})
        entities = entity_state.get("entities", {}) if isinstance(entity_state, dict) else {}
        for entity in entities.values() if isinstance(entities, dict) else []:
            if not isinstance(entity, dict):
                continue
            entity_type = str(entity.get("type") or "").strip().lower()
            if entity_type not in next_entities and entity_type not in {"ip", "domain", "url"}:
                continue
            value = str(entity.get("value") or entity.get("label") or "").strip()
            if value:
                targets.append({"value": value, "type": entity_type})
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for target in targets:
            key = (target["type"], target["value"].lower())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        return deduped[:8]

    def _variants_from_bundle(self, query_bundle: Dict[str, List[str]], required_facets: List[str]) -> List[Dict[str, Any]]:
        variants: List[Dict[str, Any]] = []
        index = 0
        for backend, queries in query_bundle.items():
            for query in queries:
                facets = infer_facets_from_text(query) or required_facets[:1]
                variants.append(
                    {
                        "variant_id": f"caller_{index}",
                        "backend": backend,
                        "strategy": "caller_provided",
                        "target_facets": facets,
                        "query": query,
                        "fingerprint": build_query_fingerprint(query),
                    }
                )
                index += 1
        return variants

    def _build_query_variants(self, query_bundle: Dict[str, List[str]], required_facets: List[str], next_entities: List[str]) -> List[Dict[str, Any]]:
        strategy_by_facet = {
            "user": "auth_baseline",
            "session": "session_linkage",
            "host": "host_timeline",
            "process": "process_lineage",
            "network": "network_egress",
        }
        reason_by_strategy = {
            "auth_baseline": "Establish baseline authentication activity for the user or account.",
            "session_linkage": "Link logon/session identifiers to host and user evidence.",
            "host_timeline": "Build host-local context around the investigated activity.",
            "process_lineage": "Look for execution lineage that explains follow-on behavior.",
            "network_egress": "Check outbound or remote communication around the focus entity.",
            "focused_entity": "Start with the primary focus entity before broader pivots.",
        }
        variants: List[Dict[str, Any]] = []
        for index, query in enumerate(query_bundle.get("splunk") or query_bundle.get("spl") or []):
            facets = infer_facets_from_text(query) or required_facets[:1]
            strategy = next((strategy_by_facet.get(facet) for facet in facets if facet in strategy_by_facet), "focused_entity")
            variants.append(
                {
                    "variant_id": f"splunk_{index}",
                    "backend": "splunk",
                    "strategy": strategy,
                    "target_facets": facets,
                    "expected_entities": [entity for entity in next_entities if entity in facets],
                    "query": query,
                    "reason": reason_by_strategy.get(strategy, reason_by_strategy["focused_entity"]),
                    "fingerprint": build_query_fingerprint(query),
                }
            )
        return variants

    def _validation_metadata(
        self,
        query_bundle: Dict[str, List[str]],
        query_variants: List[Dict[str, Any]],
        required_facets: List[str],
        max_results: int,
    ) -> Dict[str, Any]:
        executable = query_bundle.get("splunk") or query_bundle.get("spl") or []
        variant_facets: List[str] = []
        for variant in query_variants:
            variant_facets.extend([str(item) for item in variant.get("target_facets", []) if str(item).strip()])
        missing_variant_facets = [facet for facet in required_facets if facet not in set(variant_facets)]
        return {
            "schema_version": "log_query_plan.v1",
            "safe_query_family": "bounded_splunk_search",
            "executable_query_count": len(executable),
            "max_results": max_results,
            "required_facets_without_variant": missing_variant_facets,
            "coverage_contract": "Coverage metadata describes query/result evidence gaps only; it is not a deterministic verdict.",
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
        if "@" not in text and (any(token in lowered for token in ("ws-", "srv-", "host-", "endpoint", "device")) or re.fullmatch(r"[a-z0-9]+-[a-z0-9_.-]+", lowered)):
            return "host"
        if any(token in lowered for token in ("alice", "bob", "svc_", "user", "admin")):
            return "user"
        return ""

    def _extract_wmi_alert(self, text: str) -> Dict[str, str]:
        raw = str(text or "")
        lowered = raw.lower()
        if "wmi" not in lowered and "get-wmiobject" not in lowered:
            return {}
        fields: Dict[str, str] = {}
        for label in "Event ID|Rule Name|Alert Type|Severity|Alert Time|Investigation Start Time|Analyst|Alert Details".split("|"):
            match = re.search(rf"\b{label}\s*:?\s+(.*?)(?=\s+\b(?:Event ID|Rule Name|Alert Type|Severity|Alert Time|Investigation Start Time|Analyst|Alert Details)\b\s*:?|$)", raw, re.IGNORECASE)
            if match:
                fields[label.lower().replace(" ", "_")] = match.group(1).strip().rstrip(".")
        cmd = re.search(r"\b(Get-WmiObject\s+-Class\s+[A-Za-z0-9_]+)\b", raw, re.IGNORECASE)
        if cmd:
            fields["command_line"] = cmd.group(1)
        host = re.search(r"\bon\s+([A-Z0-9][A-Z0-9_.-]*-[A-Z0-9_.-]+)\b", raw, re.IGNORECASE)
        if host:
            fields["host"] = host.group(1).rstrip(".")
        if fields.get("alert_time"):
            fields["timerange"] = self._alert_time_window(fields["alert_time"])
        return fields if fields.get("host") or fields.get("command_line") or fields.get("rule_name") else {}

    def _alert_time_window(self, value: str) -> str:
        raw = str(value or "").strip()
        for fmt in ("%b %d %Y, %I:%M %p", "%B %d %Y, %I:%M %p", "%Y-%m-%d %H:%M:%S"):
            try:
                event_time = datetime.strptime(raw, fmt)
                earliest = event_time - timedelta(minutes=15)
                latest = event_time + timedelta(minutes=15)
                return f"{earliest.strftime('%Y-%m-%dt%H:%M:%S')}..{latest.strftime('%Y-%m-%dt%H:%M:%S')}"
            except ValueError:
                continue
        return raw

    def _build_wmi_alert_query_bundle(self, event: Dict[str, str], max_results: int) -> Dict[str, List[str]]:
        def q(value: str) -> str:
            return str(value or "").replace('"', '\\"')
        host = q(event.get("host", ""))
        command = q(event.get("command_line", "Get-WmiObject"))
        rule = q(event.get("rule_name", ""))
        event_id = q(event.get("event_id", ""))
        host_scope = f'(host="{host}" OR Computer="{host}" OR ComputerName="{host}")' if host else ""
        proc_base = "search index=* (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=*sysmon* OR sourcetype=WinEventLog:* OR sourcetype=*PowerShell* OR EventCode=1 OR EventCode=4688 OR EventCode=4104)"
        detect_base = "search index=* (sourcetype=*alert* OR sourcetype=*detection* OR source=*alert* OR source=*detection*)"
        command_query = f'{proc_base} {host_scope} (CommandLine="*{command}*" OR Process_Command_Line="*{command}*" OR process="*{command}*") | head {max_results}'
        host_timeline = f'{proc_base} {host_scope} (CommandLine="*Wmi*" OR CommandLine="*Get-WmiObject*" OR Image="*wmic*" OR ParentImage="*powershell*") | head {max_results}'
        detection = f'{detect_base} {host_scope} (rule_name="*{rule}*" OR signature="*{rule}*" OR EventCode="{event_id}" OR event_id="{event_id}") | head {max_results}'
        return {"splunk": [command_query, host_timeline, detection], "generic": ["WMI alert pivots use host, command line, rule name, and Windows process telemetry fields."]}

    def _extract_sysmon_event(self, text: str) -> Dict[str, str]:
        raw = str(text or "")
        fields = {}
        wanted = {"computer", "host", "user", "processguid", "parentprocessguid", "image", "parentimage", "hashes", "commandline", "utcTime", "utctime", "sourcetype"}
        for key, value in re.findall(r"(?im)^\s*([A-Za-z][A-Za-z0-9_ ]{1,40})\s*[:=]\s*(.+?)\s*$", raw):
            normalized = key.replace(" ", "").lower()
            if normalized in {item.lower() for item in wanted}:
                fields[normalized] = value.strip().strip('"')
        if not ({"processguid", "parentprocessguid", "image", "parentimage", "commandline"} & set(fields)):
            return {}
        return fields

    def _build_sysmon_query_bundle(self, event: Dict[str, str], max_results: int) -> Dict[str, List[str]]:
        def q(value: str) -> str:
            return str(value or "").replace('"', '\\"')
        host = q(event.get("computer") or event.get("host") or "")
        user = q(event.get("user", ""))
        process_guid = q(event.get("processguid", ""))
        parent_guid = q(event.get("parentprocessguid", ""))
        image = q(event.get("image", ""))
        parent_image = q(event.get("parentimage", ""))
        commandline = q(event.get("commandline", ""))
        hash_clause = ""
        for part in re.split(r"[,;\s]+", event.get("hashes", "")):
            if "=" in part:
                name, value = part.split("=", 1)
                if name.lower() in {"sha256", "sha1", "md5"} and value:
                    hash_clause += f' OR {name.lower()}="{q(value)}" OR Hashes="*{q(value)}*"'
        base = "search index=* (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=*sysmon* OR EventCode=1)"
        scope = " ".join(item for item in [
            f'(Computer="{host}" OR host="{host}" OR ComputerName="{host}")' if host else "",
            f'User="{user}"' if user else "",
        ] if item)
        process = " OR ".join(item for item in [
            f'ProcessGuid="{process_guid}"' if process_guid else "",
            f'ParentProcessGuid="{parent_guid}"' if parent_guid else "",
            f'Image="{image}"' if image else "",
            f'ParentImage="{parent_image}"' if parent_image else "",
        ] if item)
        exact = f'{base} {scope} ({process}{hash_clause}) | head {max_results}' if process or hash_clause else f'{base} {scope} | head {max_results}'
        tree = f'{base} (ProcessGuid="{process_guid}" OR ParentProcessGuid="{process_guid}" OR ParentProcessGuid="{parent_guid}") | head {max_results}' if process_guid or parent_guid else exact
        cmd = f'{base} {scope} CommandLine="*{commandline[:120]}*" | head {max_results}' if commandline else exact
        return {"splunk": [exact, tree, cmd][:3], "generic": ["Sysmon pivots use concrete ProcessGuid/ParentProcessGuid/host/user/image/hash fields."]}

    def _extract_fortigate_event(self, text: str) -> Dict[str, str]:
        raw = str(text or "")
        pairs: Dict[str, str] = {}
        for key, value in self._FORTIGATE_KV_RE.findall(raw):
            lowered = key.lower()
            if lowered in self._FORTIGATE_FIELDS:
                pairs[lowered] = value.strip().strip('"')
        if not ({"srcip", "dstip", "devname", "devid", "sessionid"} & set(pairs)):
            return {}
        timerange = self._historical_timerange(pairs.get("date"), pairs.get("time"))
        if timerange:
            pairs["timerange"] = timerange
        return pairs

    def _historical_timerange(self, date_text: Optional[str], time_text: Optional[str]) -> str:
        if not date_text:
            return ""
        try:
            event_time = datetime.strptime(f"{date_text} {time_text or '00:00:00'}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return ""
        earliest = event_time - timedelta(minutes=10)
        latest = event_time + timedelta(minutes=10)
        return f"{earliest.strftime('%Y-%m-%dt%H:%M:%S')}..{latest.strftime('%Y-%m-%dt%H:%M:%S')}"

    def _build_fortigate_query_bundle(self, event: Dict[str, str], max_results: int) -> Dict[str, List[str]]:
        def q(value: str) -> str:
            return str(value or "").replace('"', '\\"')

        device = q(event.get("devname", ""))
        devid = q(event.get("devid", ""))
        srcip = q(event.get("srcip", ""))
        dstip = q(event.get("dstip", ""))
        srcport = q(event.get("srcport", ""))
        dstport = q(event.get("dstport", ""))
        sessionid = q(event.get("sessionid", ""))
        service = q(event.get("service", ""))
        action = q(event.get("action", ""))
        event_type = q(event.get("type", ""))
        subtype = q(event.get("subtype", ""))
        srccountry = q(event.get("srccountry", ""))
        dstcountry = q(event.get("dstcountry", ""))
        crlevel = q(event.get("crlevel", ""))
        crscore = q(event.get("crscore", ""))
        device_clause = " OR ".join(item for item in [
            f'devname="{device}"' if device else "",
            f'devid="{devid}"' if devid else "",
        ] if item) or '(sourcetype=*fortigate* OR device_vendor=Fortinet)'
        endpoint_clause = " ".join(item for item in [
            f'(srcip="{srcip}" OR src_ip="{srcip}" OR source_ip="{srcip}")' if srcip else "",
            f'(dstip="{dstip}" OR dest_ip="{dstip}" OR dst_ip="{dstip}" OR destination_ip="{dstip}")' if dstip else "",
            f'(sessionid="{sessionid}" OR session_id="{sessionid}" OR session="{sessionid}")' if sessionid else "",
            f'(service="{service}" OR app="{service}")' if service else "",
            f'(dstport="{dstport}" OR dest_port="{dstport}" OR dst_port="{dstport}")' if dstport else "",
        ] if item)
        exact = f'search ({device_clause}) {endpoint_clause} | head {max_results}'
        src_pivot = (
            f'search ({device_clause}) (srcip="{srcip}" OR src_ip="{srcip}" OR source_ip="{srcip}") '
            f'| stats count by dstip,dstport,service,action'
        ) if srcip else exact
        dst_pivot = (
            f'search ({device_clause}) (dstip="{dstip}" OR dest_ip="{dstip}" OR dst_ip="{dstip}") '
            f'| stats count by srcip,srccountry,dstport,service,action'
        ) if dstip else exact
        allow_deny = f'search ({device_clause}) '
        if srcip and dstip:
            allow_deny += f'(srcip="{srcip}" OR src_ip="{srcip}") (dstip="{dstip}" OR dest_ip="{dstip}" OR dst_ip="{dstip}") '
        allow_deny += '(action=deny OR action=allow OR action=allowed) | stats count by srcip,dstip,dstport,service,action'
        comments = [
            f"Deterministically extracted FortiGate event: srcip={srcip}, dstip={dstip}, sessionid={sessionid}, service={service}, action={action}.",
            f"Additional extracted context: srcport={srcport}, type={event_type}, subtype={subtype}, srccountry={srccountry}, dstcountry={dstcountry}, crlevel={crlevel}, crscore={crscore}.",
        ]
        return {"splunk": [exact, src_pivot, dst_pivot, allow_deny][:3], "generic": comments[:2]}

    @staticmethod
    def _is_bad_focus_candidate(value: str) -> bool:
        text = str(value or "").strip().lower()
        return not text or text.startswith("/") or "search_logs" in text or "threat logs" in text
