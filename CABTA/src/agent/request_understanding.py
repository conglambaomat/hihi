"""Deterministic analyst request understanding for Phase 1 orchestration.

The extractor intentionally uses simple, auditable heuristics. It produces an
ObjectiveContract for additive metadata while legacy routing remains intact.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional

from .capability_actions import make_action
from .llm_request_interpreter import SOCInterpretationResult
from .objective_model import ObjectiveContract, ObjectiveModelBuilder, RequestUnderstanding
from .soc_interpretation_schema import SOCApprovalNeed, SOCInterpretation, SOCMissingInput, compact_for_task_state
from .soc_task_state import SOCTaskState


class RequestUnderstandingExtractor:
    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    _CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    def __init__(self, objective_builder: Optional[ObjectiveModelBuilder] = None):
        self.objective_builder = objective_builder or ObjectiveModelBuilder()

    def extract(self, message: str, context: Optional[Dict[str, Any]] = None) -> RequestUnderstanding:
        context = dict(context or {})
        raw_text = str(message or "")
        lowered = raw_text.lower()
        entities = self._extract_entities(raw_text, context)
        requested_backends = self._requested_backends(lowered, context)
        timerange = self._timerange(raw_text, context)
        alert_fields = self._extract_alert_fields(raw_text)
        if alert_fields.get("alert_time") and timerange.get("source") == "default":
            timerange = self._timerange_from_alert_time(alert_fields["alert_time"])
        entities.extend(self._extract_soc_entities(raw_text))
        entities.extend(self._alert_entities(alert_fields))
        entities = self._dedupe_entities(entities)
        intent, domain, capabilities = self._classify_schema_only(lowered, entities, requested_backends, context)
        constraints = self._constraints(lowered, timerange, requested_backends)
        output_preferences = self._output_preferences(lowered)
        uncertainty = [] if raw_text.strip() else ["empty_request"]
        if intent == "clarify_request":
            uncertainty.append("request_is_vague")
        safety_flags = ["approval_required"] if any(token in lowered for token in ("contain", "isolate", "block", "disable account", "disable user", "quarantine")) else []
        return RequestUnderstanding(
            raw_text=raw_text,
            intent=intent,
            domain=domain,
            analyst_objective=raw_text.strip() or "Clarify analyst objective before tool execution.",
            entities=entities,
            requested_backends=requested_backends,
            timerange=timerange,
            output_preferences=output_preferences,
            uncertainty=uncertainty,
            safety_flags=safety_flags,
            capabilities_required=capabilities,
            constraints=constraints,
            source_metadata={
                "extractor": "deterministic/request-understanding/v1",
                "context_keys": sorted(str(key) for key in context.keys()),
            },
        )

    def build_objective_contract(self, message: str, metadata: Optional[Dict[str, Any]] = None) -> ObjectiveContract:
        metadata = dict(metadata or {})
        understanding = self.extract(message, metadata)
        return self.objective_builder.build(understanding, runtime=metadata)

    def _classify_schema_only(self, lowered: str, entities: List[Dict[str, Any]], backends: List[str], context: Dict[str, Any]) -> tuple[str, str, List[str]]:
        """Conservative non-LLM classifier for schema/parser-backed evidence only."""
        context_text = " ".join(str(value).lower() for value in context.values() if isinstance(value, (str, int, float)))
        combined = f"{lowered} {context_text}".strip()
        normalized_combined = self._normalize_natural_chat_text(combined)
        if self._looks_inline_log_artifact(combined):
            return "log_artifact_analysis", "log_security", ["log.analyze.inline", "findings.correlate"]
        if self._looks_like_soc_alert(combined):
            return "alert_investigation", "log_security", ["log.search", "findings.correlate"]
        if self._is_capability_or_help_greeting(normalized_combined):
            return "config_capability_question", "config", ["config.capability.explain"]
        if any(token in combined for token in ("contain", "isolate", "block", "disable account", "disable user", "quarantine", "eradicate")):
            caps = ["log.search", "ir.approval.request"]
            if "contain" in combined or "isolate" in combined:
                caps.append("ir.host.contain.propose")
            if "disable" in combined:
                caps.append("ir.user.disable.propose")
            if "block" in combined:
                caps.append("ir.network.block.propose")
            return "incident_response", "incident_response", list(dict.fromkeys(caps))
        if any(token in combined for token in ("what did you find", "what should i do next", "summarize findings", "recap findings")):
            return "followup_summary", "case_follow_up", ["case.summarize"]
        if self._looks_inline_email(combined):
            return "phishing_email_analysis", "email", ["email.parse.inline", "ioc.extract"]
        if re.search(r"[A-Za-z]:[\\/]", combined):
            return "malware_file_analysis", "file", ["file.analyze.static"]
        if backends or re.search(r"\b(?:splunk|siem|sourcetype|eventcode|threat hunt|hunt)\b", combined):
            return "threat_hunt", "log_security", ["log.search", "findings.correlate"]
        if entities and any(item.get("type") in {"ip", "domain", "url", "hash", "cve"} for item in entities):
            return "ioc_triage", "ioc", ["ioc.enrich"]
        return "clarify_request", "general", ["case.context.read"]

    @staticmethod
    def _normalize_natural_chat_text(text: str) -> str:
        raw = str(text or "").strip().lower()
        folded = unicodedata.normalize("NFKD", raw)
        simplified = "".join(ch for ch in folded if not unicodedata.combining(ch))
        return re.sub(r"\s+", " ", simplified).strip()

    @classmethod
    def _is_capability_or_help_greeting(cls, normalized_text: str) -> bool:
        text = str(normalized_text or "").strip().lower()
        if not text:
            return False
        greeting_tokens = ("hello", "hi", "hey", "xin chao", "chao", "good morning", "good afternoon")
        capability_tokens = (
            "what can you do",
            "what do you do",
            "how can you help",
            "help with capabilities",
            "capability",
            "capabilities",
            "ban co the lam gi",
            "ban co the lam duoc gi",
            "ban lam duoc gi",
            "co the lam gi",
            "co the lam duoc gi",
            "lam duoc gi",
            "giup toi",
            "tro giup",
        )
        has_greeting = any(token in text for token in greeting_tokens)
        has_capability = any(token in text for token in capability_tokens)
        if has_capability:
            return True
        return has_greeting and len(text.split()) <= 8

    def _extract_entities(self, text: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        entities: List[Dict[str, Any]] = []

        def add(entity_type: str, value: str, source: str = "message") -> None:
            value = str(value or "").strip()
            if value and not any(item.get("type") == entity_type and item.get("value") == value for item in entities):
                entities.append({"type": entity_type, "value": value, "source": source, "confidence": 0.8, "role": "observable"})

        for value in self._EMAIL_RE.findall(text):
            add("email", value.lower())
        for value in self._IP_RE.findall(text):
            add("ip", value)
        for value in self._DOMAIN_RE.findall(text):
            if "@" not in value:
                add("domain", value.lower())
        for value in self._HASH_RE.findall(text):
            add("hash", value.lower())
        for value in self._CVE_RE.findall(text):
            add("cve", value.upper())
        for key in ("observables", "observable_summary", "entity_hints"):
            value = context.get(key)
            if isinstance(value, list):
                for item in value:
                    add("context", str(item), source=key)
            elif value:
                add("context", str(value), source=key)
        return entities[:16]

    def _requested_backends(self, lowered: str, context: Dict[str, Any]) -> List[str]:
        backends: List[str] = []
        for token, backend in (("splunk", "splunk"), ("fortigate", "fortigate"), ("fortinet", "fortigate"), ("siem", "siem"), ("firewall", "firewall")):
            if token in lowered and backend not in backends:
                backends.append(backend)
        explicit = context.get("requested_backends") or context.get("backend")
        if isinstance(explicit, list):
            for item in explicit:
                value = str(item).strip().lower()
                if value and value not in backends:
                    backends.append(value)
        elif explicit:
            value = str(explicit).strip().lower()
            if value and value not in backends:
                backends.append(value)
        return backends

    def _timerange(self, text: str, context: Dict[str, Any]) -> Dict[str, Any]:
        lowered = text.lower()
        explicit = context.get("effective_timerange") or context.get("timerange") or context.get("requested_timerange")
        if explicit:
            return {"requested": str(explicit), "value": str(explicit), "effective": str(explicit), "source": "metadata", "normalization_reason": "metadata_timerange_preserved"}
        match = re.search(r"\b(?:over\s+the\s+)?(last|past)\s+(\d+)\s*(m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks)\b", lowered)
        if match:
            unit = match.group(3)
            normalized_unit = {"m": "m", "min": "m", "minute": "m", "minutes": "m", "h": "h", "hour": "h", "hours": "h", "d": "d", "day": "d", "days": "d", "w": "w", "week": "w", "weeks": "w"}[unit]
            value = f"{match.group(2)}{normalized_unit}"
            requested = f"last_{match.group(2)}_{'days' if normalized_unit == 'd' else 'hours' if normalized_unit == 'h' else 'weeks' if normalized_unit == 'w' else 'minutes'}"
            return {"requested": requested, "value": value, "effective": value, "source": "analyst_request", "normalization_reason": "message_timerange_normalized"}
        if "yesterday" in lowered:
            return {"requested": "yesterday", "value": "yesterday", "effective": "yesterday", "source": "analyst_request", "normalization_reason": "explicit_yesterday_preserved"}
        if any(token in lowered for token in ("historical", "all time", "all-time", "all logs", "entire history")):
            return {"requested": "historical", "value": "historical", "effective": "historical", "source": "analyst_request", "mode": "broad_historical", "normalization_reason": "explicit_historical_request_preserved"}
        if any(token in lowered for token in ("today", "24h", "last day")):
            return {"requested": "24h", "value": "24h", "effective": "24h", "source": "message", "normalization_reason": "message_timerange_normalized"}
        return {"requested": "24h", "value": "24h", "effective": "24h", "source": "default", "normalization_reason": "default_timerange_applied"}

    def _constraints(self, lowered: str, timerange: Dict[str, Any], backends: List[str]) -> Dict[str, Any]:
        constraints: Dict[str, Any] = {
            "timerange_source": timerange.get("source", "default"),
            "requested_backend_required": bool(backends),
        }
        if timerange.get("effective") in {"historical", "all-time", "all time"}:
            constraints["historical_scope_requested"] = True
        if any(token in lowered for token in ("evidence", "prove", "show logs", "find logs", "hunt")):
            constraints["evidence_first"] = True
        return constraints

    def _output_preferences(self, lowered: str) -> List[str]:
        preferences: List[str] = []
        if "summary" in lowered:
            preferences.append("summary")
        if "timeline" in lowered:
            preferences.append("timeline")
        if "rule" in lowered or "sigma" in lowered or "spl" in lowered:
            preferences.append("detection_rule")
        return preferences

    @staticmethod
    def _looks_inline_email(text: str) -> bool:
        return any(token in text for token in ("subject:", "from:", "to:", "http://", "https://"))

    @staticmethod
    def _looks_like_soc_alert(text: str) -> bool:
        lowered = str(text or "").lower()
        alert_markers = ("alert type", "alert time", "alert details", "rule name", "severity", "investigation start time")
        return "alert" in lowered and sum(1 for marker in alert_markers if marker in lowered) >= 2

    @staticmethod
    def _extract_alert_fields(text: str) -> Dict[str, str]:
        raw = str(text or "")
        labels = "Event ID|Rule Name|Alert Type|Severity|Alert Time|Investigation Start Time|Analyst|Alert Details"
        fields: Dict[str, str] = {}
        for label in labels.split("|"):
            match = re.search(rf"\b{label}\s*:?[\s]+(.*?)(?=\s+\b(?:{labels})\b\s*:?|$)", raw, re.IGNORECASE)
            if match:
                fields[label.lower().replace(" ", "_")] = match.group(1).strip().rstrip(".")
        cmd = re.search(r"\b(Get-WmiObject\s+-Class\s+[A-Za-z0-9_]+)\b", raw, re.IGNORECASE)
        if cmd:
            fields["command_line"] = cmd.group(1)
        host = re.search(r"\bon\s+([A-Z0-9][A-Z0-9_.-]*-[A-Z0-9_.-]+)\b", raw, re.IGNORECASE)
        if host:
            fields["host"] = host.group(1).rstrip(".")
        return fields

    @staticmethod
    def _alert_entities(fields: Dict[str, str]) -> List[Dict[str, Any]]:
        entities: List[Dict[str, Any]] = []
        for key, etype, role in (("host", "host", "asset"), ("rule_name", "rule", "detection_rule"), ("event_id", "event_id", "event_code"), ("command_line", "command_line", "process_command")):
            value = fields.get(key)
            if value:
                entities.append({"type": etype, "value": value, "source": "alert_text_parser", "confidence": 0.88, "role": role})
        if "wmi" in (fields.get("alert_details", "") + " " + fields.get("command_line", "")).lower():
            entities.append({"type": "technique", "value": "System Information Discovery via WMI", "source": "alert_text_parser", "confidence": 0.84, "role": "attack_technique"})
        return entities

    @staticmethod
    def _timerange_from_alert_time(alert_time: str) -> Dict[str, Any]:
        value = str(alert_time or "").strip()
        return {"requested": value, "value": value, "effective": value, "source": "alert_time", "normalization_reason": "alert_time_preserved_for_query_window", "window_hint": "-30m..+2h"}

    @staticmethod
    def _looks_inline_log_artifact(text: str) -> bool:
        lowered = str(text or "").lower()
        kv_markers = ("sourcetype=", "source=", "src_ip=", "dest_ip=", "dest_port=", "eventcode=", "host=")
        splunk_markers = ("stream:tcp", "stream:udp", "splunk", "index=", "_time=")
        has_log_kv = sum(1 for marker in kv_markers if marker in lowered) >= 2
        has_network_tuple = ("src_ip=" in lowered or "srcip=" in lowered) and ("dest_ip=" in lowered or "dstip=" in lowered or "dest_port=" in lowered)
        return bool((has_log_kv and any(marker in lowered for marker in splunk_markers)) or (has_network_tuple and ("source=" in lowered or "sourcetype=" in lowered)))

    def _extract_soc_entities(self, text: str) -> List[Dict[str, Any]]:
        entities: List[Dict[str, Any]] = []
        def add(entity_type: str, value: str, role: str = "entity") -> None:
            value = str(value or "").strip().strip(",.;")
            if value:
                entities.append({"type": entity_type, "value": value, "source": "message", "confidence": 0.82, "role": role})
        for match in re.finditer(r"\buser\s+([A-Za-z0-9_.\-]+)", text, re.IGNORECASE):
            add("user", match.group(1), "account")
        for match in re.finditer(r"\bhost\s+([A-Za-z0-9_.\-]+)", text, re.IGNORECASE):
            add("host", match.group(1), "asset")
        for match in re.finditer(r"\b(?:from|src(?:_ip)?)\s+(\d{1,3}(?:\.\d{1,3}){3})", text, re.IGNORECASE):
            add("ip", match.group(1), "source_ip")
        for match in re.finditer(r"\b(?:to|dest(?:ination)?(?:_ip)?)\s+(\d{1,3}(?:\.\d{1,3}){3})", text, re.IGNORECASE):
            add("ip", match.group(1), "destination_ip")
        return entities

    @staticmethod
    def _dedupe_entities(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()
        for item in entities:
            key = (item.get("type"), item.get("value"), item.get("role"))
            if item.get("type") and item.get("value") and key not in seen:
                seen.add(key)
                out.append(item)
        return out[:24]


class SOCRequestInterpreter:
    """Create canonical SOCTaskState from LLM-first or deterministic understanding."""

    def __init__(self, extractor: Optional[RequestUnderstandingExtractor] = None, *, llm_interpreter: Any = None, mode: str = "disabled"):
        self.extractor = extractor or RequestUnderstandingExtractor()
        self.llm_interpreter = llm_interpreter
        self.mode = self._normalize_mode(mode)

    @staticmethod
    def _normalize_mode(mode: str) -> str:
        value = str(mode or "disabled").strip().lower()
        return value if value in {"disabled", "shadow", "primary"} else "disabled"

    def interpret(self, message: str, context: Optional[Dict[str, Any]] = None) -> SOCTaskState:
        """Synchronous compatibility path; primary LLM should use interpret_async."""
        return self._deterministic_task(message, context or {})

    async def interpret_async(self, message: str, context: Optional[Dict[str, Any]] = None) -> SOCTaskState:
        context = dict(context or {})
        mode = self._normalize_mode(context.get("llm_request_interpreter_mode") or self.mode)
        if mode in {"shadow", "primary"} and self.llm_interpreter is not None:
            result = await self.llm_interpreter.interpret(message, context)
            if mode == "primary":
                if result.accepted and result.interpretation is not None:
                    return self._task_from_interpretation(result.interpretation, result, context)
                return self._clarification_task_from_failed_llm(message, context, result)
            task = self._deterministic_task(message, context)
            task.field_sources["soc_interpretation_shadow"] = result.to_dict()
            task.add_progress(
                "llm_interpretation_shadow_recorded",
                status=result.status,
                accepted=result.accepted,
                fallback_used=bool(result.fallback_metadata.get("used")),
            )
            return task
        return self._deterministic_task(message, context)

    def _deterministic_task(self, message: str, context: Dict[str, Any]) -> SOCTaskState:
        context = dict(context or {})
        understanding = self.extractor.extract(message, context)
        objective = self.extractor.objective_builder.build(understanding, runtime=context)
        role = "follow_up" if understanding.intent == "followup_summary" or context.get("parent_task_id") or context.get("previous_soc_task_state") else "new_task"
        task = SOCTaskState(
            session_id=str(context.get("session_id") or ""),
            parent_task_id=context.get("parent_task_id") or (context.get("previous_soc_task_state") or {}).get("task_id") if isinstance(context.get("previous_soc_task_state"), dict) else None,
            raw_request=understanding.raw_text,
            conversation_role=role,
            lane="network_log_hunt" if understanding.domain == "log_security" else understanding.domain,
            intent=understanding.intent,
            analyst_objective=understanding.analyst_objective,
            entities=list(understanding.entities),
            requested_backends=list(understanding.requested_backends),
            timerange=dict(understanding.timerange),
            required_capabilities=list(understanding.capabilities_required),
            objective_contract=objective.to_dict(),
            field_sources={"interpreter": understanding.source_metadata, "timerange": understanding.timerange.get("source")},
        )
        self._attach_artifacts(task)
        actions = [make_action(task, capability).to_dict() for capability in task.required_capabilities]
        task.actions = actions
        task.add_progress("task_interpreted", intent=task.intent, lane=task.lane, capabilities=task.required_capabilities)
        return task

    def _task_from_interpretation(self, interpretation: SOCInterpretation, result: SOCInterpretationResult, context: Dict[str, Any]) -> SOCTaskState:
        objective = self.extractor.objective_builder.build(
            RequestUnderstanding(
                raw_text=interpretation.raw_request,
                intent=interpretation.primary_intent,
                domain="log_security" if interpretation.lane == "network_log_hunt" else interpretation.lane,
                analyst_objective=(interpretation.objectives[0].summary if interpretation.objectives else interpretation.raw_request),
                entities=[entity.to_dict() for entity in interpretation.entities],
                requested_backends=list(interpretation.requested_backends),
                timerange=dict(interpretation.timerange or {"requested": "24h", "effective": "24h", "source": "default"}),
                output_preferences=list(interpretation.output_preferences),
                uncertainty=[],
                safety_flags=list(interpretation.safety_flags),
                capabilities_required=[need.capability_id for need in interpretation.capability_needs],
                constraints={"llm_interpretation_primary": True},
                source_metadata={"extractor": "llm-request-interpreter/v1", "interpretation_id": interpretation.interpretation_id},
            ),
            runtime=context,
        )
        role = interpretation.conversation_role
        if role == "capability_question":
            role = "new_task"
        task = SOCTaskState(
            session_id=str(context.get("session_id") or ""),
            parent_task_id=context.get("parent_task_id") or (context.get("previous_soc_task_state") or {}).get("task_id") if isinstance(context.get("previous_soc_task_state"), dict) else None,
            raw_request=interpretation.raw_request,
            normalized_request=interpretation.normalized_request,
            conversation_role=role,
            lane=interpretation.lane,
            intent=interpretation.primary_intent,
            analyst_objective=(interpretation.objectives[0].summary if interpretation.objectives else interpretation.raw_request),
            entities=[entity.to_dict() for entity in interpretation.entities],
            artifacts=list(interpretation.artifacts),
            requested_backends=list(interpretation.requested_backends),
            timerange=dict(interpretation.timerange or {}),
            required_capabilities=[need.capability_id for need in interpretation.capability_needs],
            objective_contract=objective.to_dict(),
            field_sources={
                "interpreter": "llm-request-interpreter/v1",
                "interpretation": compact_for_task_state(interpretation),
                "soc_interpretation_result": result.to_dict(),
            },
        )
        self._attach_artifacts(task)
        task.actions = [make_action(task, need.capability_id, rationale=need.reason).to_dict() for need in interpretation.capability_needs]
        task.pending_clarifications = [self._missing_input_payload(item) for item in interpretation.missing_inputs if item.blocking]
        task.pending_approvals = [self._approval_payload(item) for item in interpretation.approval_needs]
        task.add_progress(
            "llm_interpretation_accepted",
            interpretation_id=interpretation.interpretation_id,
            intent=task.intent,
            lane=task.lane,
            confidence=interpretation.confidence,
            capabilities=task.required_capabilities,
            repair_attempted=bool(result.repair_metadata.get("attempted")),
        )
        return task

    @staticmethod
    def _missing_input_payload(item: SOCMissingInput) -> Dict[str, Any]:
        return {
            "missing_id": item.missing_id,
            "field": item.field,
            "capability_id": item.capability_id,
            "question": item.clarification_question,
            "blocking": item.blocking,
            "allowed_alternatives": list(item.allowed_alternatives),
        }

    @staticmethod
    def _approval_payload(item: SOCApprovalNeed) -> Dict[str, Any]:
        return {
            "approval_id": item.approval_id,
            "action_type": item.action_type,
            "capability_id": item.capability_id,
            "target_type": item.target_type,
            "target": item.target,
            "approval_required": True,
            "execution_allowed": False,
            "reason": item.reason,
        }

    def _clarification_task_from_failed_llm(self, message: str, context: Dict[str, Any], result: SOCInterpretationResult) -> SOCTaskState:
        deterministic = self._deterministic_task(message, context)
        explicit_log_request = bool(
            "log.search" in (deterministic.required_capabilities or [])
            and (
                deterministic.intent in {"alert_investigation", "threat_hunt", "log_artifact_analysis"}
                or deterministic.requested_backends
            )
        )
        if explicit_log_request:
            deterministic.field_sources["soc_interpretation_result"] = result.to_dict()
            deterministic.field_sources["interpreter"] = {
                "primary": "llm-request-interpreter/v1",
                "fallback": "deterministic_explicit_log_request",
                "reason": "schema_llm_rejected_but_request_explicitly_requires_log_search",
            }
            deterministic.add_progress(
                "llm_interpretation_rejected_explicit_log_fallback_used",
                status=result.status,
                errors=result.validation.errors,
                capabilities=deterministic.required_capabilities,
            )
            return deterministic
        task = SOCTaskState(
            session_id=str(context.get("session_id") or ""),
            parent_task_id=context.get("parent_task_id"),
            raw_request=str(message or ""),
            conversation_role="new_task",
            lane="general",
            intent="clarify_request",
            analyst_objective=str(message or ""),
            required_capabilities=["case.context.read"],
            field_sources={"interpreter": "llm-request-interpreter/v1", "soc_interpretation_result": result.to_dict()},
        )
        task.pending_clarifications = [{"field": "soc_interpretation", "question": "I could not safely interpret this request with the schema-constrained LLM path. Please clarify the objective or provide the specific artifact/observable.", "blocking": True}]
        task.add_progress("llm_interpretation_rejected_no_heuristic_fallback", status=result.status, errors=result.validation.errors)
        return task

    def _attach_artifacts(self, task: SOCTaskState) -> None:
        raw = task.raw_request
        lowered = raw.lower()
        if self.extractor._looks_inline_log_artifact(lowered):
            fields = self._parse_kv_fields(raw)
            backend = "splunk" if "splunk" in lowered or fields.get("source", "").startswith("stream:") or fields.get("sourcetype", "").startswith("stream:") else ""
            if backend and backend not in task.requested_backends:
                task.requested_backends.append(backend)
            task.lane = "network_log_hunt" if task.lane in {"email", "ioc", "general", "network"} else task.lane
            task.intent = "log_artifact_analysis" if task.intent in {"phishing_email_analysis", "ioc_triage", "general_investigation"} else task.intent
            if "log.analyze.inline" not in task.required_capabilities:
                task.required_capabilities = ["log.analyze.inline", *[cap for cap in task.required_capabilities if cap != "log.analyze.inline"]]
            task.add_artifact(
                "inline_log_event",
                raw_text=raw,
                backend=backend or (task.requested_backends[0] if task.requested_backends else "inline"),
                fields=fields,
                source=fields.get("source") or fields.get("sourcetype") or "message",
                sourcetype=fields.get("sourcetype") or fields.get("source") or "",
            )
        if any(token in lowered for token in ("subject:", "from:", "phish", "email")) and ("http://" in lowered or "https://" in lowered or "subject:" in lowered) and not self.extractor._looks_inline_log_artifact(lowered):
            urls = re.findall(r"https?://[^\s<>'\"]+", raw)
            task.add_artifact("inline_email", raw_text=raw, urls=urls, subject=RequestUnderstandingExtractor._extract_soc_entities.__name__ and self.extractor._looks_inline_email(lowered) and self._label(raw, "subject"), sender=self._label(raw, "from"), recipient=self._label(raw, "to"))
        path_match = re.search(r"([A-Za-z]:[\\/](?:[^\r\n,;]+?))(?:\s+(?:and|but|then|please|tell|not uploaded|was not uploaded)\b|$)", raw, re.IGNORECASE)
        if path_match:
            task.add_artifact("local_path_reference", file_path=path_match.group(1).strip().rstrip(".,;:))"), declared_missing=any(token in lowered for token in ("not uploaded", "was not uploaded", "haven't uploaded", "not upload")))

    @staticmethod
    def _parse_kv_fields(raw: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_\-]*)=([^\s]+|\"[^\"]*\")", str(raw or "")):
            fields[key.lower()] = value.strip().strip('"').rstrip(",;")
        return fields

    @staticmethod
    def _label(raw: str, label: str) -> str:
        labels = "from|to|subject|date|body|url|link"
        match = re.search(rf"\b{re.escape(label)}\s*:\s*(.*?)(?=\s+\b(?:{labels})\s*:|$)", raw, re.IGNORECASE)
        return match.group(1).strip() if match else ""
