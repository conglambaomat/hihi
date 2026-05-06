"""LLM-first, schema-constrained SOC request interpreter for AISA."""

from __future__ import annotations

import inspect
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .capability_ontology import CapabilityOntology
from .soc_interpretation_schema import (
    CONFIDENCE_LABELS,
    CONVERSATION_ROLES,
    ENTITY_TYPES,
    LANES,
    MISSING_FIELDS,
    PRIMARY_INTENTS,
    SOCEntityCandidate,
    SOCInterpretation,
    SOCInterpretationValidationResult,
    allowed_capability_ids,
    validate_soc_interpretation,
)

PROMPT_VERSION = "soc-request-interpreter-prompt/v1"
INTERPRETER_VERSION = "llm-request-interpreter/v1"

ProviderCallable = Callable[[List[Dict[str, Any]], Dict[str, Any]], Awaitable[Any] | Any]


@dataclass
class SOCInterpretationResult:
    interpretation: Optional[SOCInterpretation] = None
    validation: SOCInterpretationValidationResult = field(default_factory=SOCInterpretationValidationResult)
    repair_metadata: Dict[str, Any] = field(default_factory=dict)
    fallback_metadata: Dict[str, Any] = field(default_factory=dict)
    deterministic_cross_check: Dict[str, Any] = field(default_factory=dict)
    raw_provider_metadata: Dict[str, Any] = field(default_factory=dict)
    raw_output: Any = None
    status: str = "invalid"

    @property
    def accepted(self) -> bool:
        return self.interpretation is not None and self.validation.valid and self.status == "accepted"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interpretation": self.interpretation.to_dict() if self.interpretation else None,
            "validation": self.validation.to_dict(),
            "repair_metadata": dict(self.repair_metadata or {}),
            "fallback_metadata": dict(self.fallback_metadata or {}),
            "deterministic_cross_check": dict(self.deterministic_cross_check or {}),
            "raw_provider_metadata": dict(self.raw_provider_metadata or {}),
            "status": self.status,
        }


class LLMRequestInterpreterError(RuntimeError):
    """Raised when LLM-first SOC request interpretation cannot run."""


class LLMRequestInterpreter:
    """Call an injected/provider LLM for strict JSON SOC interpretation, then validate and audit it."""

    def __init__(
        self,
        *,
        provider: Optional[ProviderCallable] = None,
        ontology: Optional[CapabilityOntology] = None,
        deterministic_extractor: Any = None,
        mode: str = "shadow",
        max_repair_attempts: int = 1,
        min_accept_confidence: float = 0.75,
        min_clarify_confidence: float = 0.50,
    ):
        self.provider = provider
        self.ontology = ontology or CapabilityOntology()
        self.deterministic_extractor = deterministic_extractor
        self.mode = self._normalize_mode(mode)
        self.max_repair_attempts = max(0, min(int(max_repair_attempts), 2))
        self.min_accept_confidence = float(min_accept_confidence)
        self.min_clarify_confidence = float(min_clarify_confidence)

    @staticmethod
    def _normalize_mode(mode: str) -> str:
        value = str(mode or "disabled").strip().lower()
        return value if value in {"disabled", "shadow", "primary"} else "disabled"

    def build_prompt(self, analyst_message: str, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        context = dict(context or {})
        capabilities = allowed_capability_ids(self.ontology)
        system = (
            "You are an AISA SOC request interpreter. Interpret the analyst request into one strict JSON object matching SOCInterpretation. "
            "You may understand goals, split mixed objectives, identify entities, choose capability needs, propose candidate log/SPL query intent, "
            "identify pivots, missing evidence, and approval needs. You do not run tools, call APIs, approve actions, or produce final security verdicts. "
            "Do not claim malware/phishing/IOC/log findings or deterministic scores. Use only allowed enum values and capability IDs. "
            "Destructive response actions must be approval needs with execution_allowed=false. Return JSON only; no markdown."
        )
        payload = {
            "analyst_message": str(analyst_message or ""),
            "conversation_context": {
                "session_id": context.get("session_id"),
                "parent_task_id": context.get("parent_task_id"),
                "previous_soc_task_state": context.get("previous_soc_task_state"),
                "prior_findings_summary": context.get("prior_findings_summary") or context.get("findings_summary"),
            },
            "runtime_context": {
                "enabled_capabilities": capabilities,
                "allowed_capability_ids": capabilities,
                "allowed_intents": sorted(PRIMARY_INTENTS),
                "allowed_lanes": sorted(LANES),
                "allowed_conversation_roles": sorted(CONVERSATION_ROLES),
                "allowed_entity_types": sorted(ENTITY_TYPES),
                "allowed_missing_fields": sorted(MISSING_FIELDS),
                "allowed_confidence_labels": sorted(CONFIDENCE_LABELS),
                "feature_flag_mode": self.mode,
            },
            "constraints": {
                "deterministic_verdict_authority": True,
                "destructive_actions_require_approval": True,
                "tools_not_executed_by_interpreter": True,
                "raw_output_must_be_json_object": True,
                "prompt_version": PROMPT_VERSION,
            },
        }
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(payload, sort_keys=True)},
        ]

    def build_request_metadata(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "mode": "schema_interpretation",
            "intent": "soc_request_interpretation",
            "response_format": {"type": "json_object"},
            "tool_choice_allowed": False,
            "tools": [],
            "prompt_version": PROMPT_VERSION,
            "schema_name": "SOCInterpretation",
            "feature_flag_mode": self.mode,
            "context_keys": sorted(str(key) for key in (context or {}).keys()),
        }

    async def interpret(self, analyst_message: str, context: Optional[Dict[str, Any]] = None) -> SOCInterpretationResult:
        context = dict(context or {})
        if self.mode == "disabled":
            raise LLMRequestInterpreterError("LLM request interpreter is disabled")
        cross_check = self._deterministic_cross_check(analyst_message, context)
        messages = self.build_prompt(analyst_message, context)
        metadata = self.build_request_metadata(context)
        raw = await self._call_provider(messages, metadata)
        if raw is None:
            raise LLMRequestInterpreterError("LLM request interpreter provider returned no response")
        parsed, parse_errors, parse_status = self._parse_json_output(raw)
        interpretation: Optional[SOCInterpretation] = None
        validation = SOCInterpretationValidationResult(parse_status=parse_status, errors=list(parse_errors))
        repair_metadata = {"attempted": False, "attempt_count": 0, "reasons": [], "final_status": "not_needed"}
        if parsed is not None and not parse_errors:
            interpretation, validation = self._validate_payload(parsed, raw, analyst_message, context, cross_check, parse_status=parse_status)
        if (parse_errors or not validation.valid or interpretation is None) and self.max_repair_attempts > 0:
            repair_metadata["attempted"] = True
            repair_metadata["attempt_count"] = 1
            repair_metadata["reasons"] = list(validation.errors or parse_errors)
            repaired_raw = await self._call_repair_provider(analyst_message, raw, validation, context)
            repaired, repaired_errors, repaired_status = self._parse_json_output(repaired_raw)
            if repaired is not None and not repaired_errors:
                interpretation, validation = self._validate_payload(repaired, repaired_raw, analyst_message, context, cross_check, parse_status="repaired_json" if repaired_status != "invalid_json" else repaired_status)
            repair_metadata["final_status"] = "repaired" if interpretation is not None and validation.valid else "failed"
            raw = repaired_raw if repaired_raw is not None else raw
        fallback_metadata = {"used": False, "mode": "none", "reason": ""}
        status = "accepted" if interpretation is not None and validation.valid else "invalid"
        if interpretation is not None:
            interpretation.repair = repair_metadata
            interpretation.fallback = fallback_metadata
            interpretation.validation = validation.to_dict()
            interpretation.validation["authoritative_for_verdict"] = False
            if interpretation.confidence < self.min_accept_confidence:
                if interpretation.confidence < self.min_clarify_confidence:
                    validation.warnings.append("low_confidence_clarification_recommended")
                    status = "needs_clarification"
                else:
                    validation.warnings.append("medium_confidence_accept_with_audit")
                    status = "accepted"
        if status not in {"accepted", "needs_clarification"}:
            fallback_metadata = {"used": False, "mode": "none", "reason": "invalid_or_unsafe_interpretation"}
        return SOCInterpretationResult(
            interpretation=interpretation if status in {"accepted", "needs_clarification"} else None,
            validation=validation,
            repair_metadata=repair_metadata,
            fallback_metadata=fallback_metadata,
            deterministic_cross_check=cross_check,
            raw_provider_metadata={"provider_available": True, "prompt_version": PROMPT_VERSION},
            raw_output=raw,
            status=status,
        )

    async def _call_provider(self, messages: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Any:
        if self.provider is None:
            raise LLMRequestInterpreterError("LLM request interpreter provider is not configured")
        result = self.provider(messages, metadata)
        if inspect.isawaitable(result):
            return await result
        return result

    async def _call_repair_provider(self, analyst_message: str, raw: Any, validation: SOCInterpretationValidationResult, context: Dict[str, Any]) -> Any:
        if self.provider is None:
            raise LLMRequestInterpreterError("LLM request interpreter repair provider is not configured")
        repair_messages = self.build_prompt(analyst_message, context)
        repair_payload = {
            "validation_errors": validation.errors,
            "validation_warnings": validation.warnings,
            "invalid_output": raw,
            "instruction": "Return one corrected strict SOCInterpretation JSON object only. No markdown. No tool execution. No verdicts.",
        }
        repair_messages.append({"role": "user", "content": json.dumps(repair_payload, sort_keys=True, default=str)})
        return await self._call_provider(repair_messages, {**self.build_request_metadata(context), "repair_attempt": True})

    def _validate_payload(self, payload: Dict[str, Any], raw: Any, analyst_message: str, context: Dict[str, Any], cross_check: Dict[str, Any], *, parse_status: str) -> tuple[Optional[SOCInterpretation], SOCInterpretationValidationResult]:
        payload = dict(payload)
        payload.setdefault("raw_request", analyst_message)
        payload.setdefault("raw_llm_output", raw)
        payload.setdefault("provenance", {})
        payload["provenance"] = {
            **dict(payload.get("provenance") or {}),
            "interpreter": INTERPRETER_VERSION,
            "prompt_version": PROMPT_VERSION,
            "ontology_version": "capability-descriptor/v1",
            "feature_flag_mode": self.mode,
            "deterministic_cross_check_version": "request-understanding/v1",
        }
        interpretation, validation = validate_soc_interpretation(payload, self.ontology, context)
        validation.parse_status = parse_status
        candidate = interpretation or SOCInterpretation.from_dict(payload)
        self._apply_cross_check(candidate, validation, cross_check, analyst_message, context)
        if validation.valid:
            interpretation = candidate
            interpretation.validation = validation.to_dict()
        else:
            interpretation = None
        return interpretation, validation

    @staticmethod
    def _parse_json_output(raw: Any) -> tuple[Optional[Dict[str, Any]], List[str], str]:
        if isinstance(raw, dict):
            return dict(raw), [], "valid_json"
        if isinstance(raw, str):
            text = raw.strip()
            try:
                parsed = json.loads(text)
                return (parsed if isinstance(parsed, dict) else None), ([] if isinstance(parsed, dict) else ["json_not_object"]), "valid_json"
            except json.JSONDecodeError:
                fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.IGNORECASE | re.DOTALL)
                if fenced:
                    try:
                        parsed = json.loads(fenced.group(1))
                        return (parsed if isinstance(parsed, dict) else None), ([] if isinstance(parsed, dict) else ["json_not_object"]), "fenced_json_extracted"
                    except json.JSONDecodeError:
                        pass
        return None, ["invalid_json"], "invalid_json"

    def _deterministic_cross_check(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if self.deterministic_extractor is None:
            return {"available": False}
        try:
            understanding = self.deterministic_extractor.extract(message, context)
            return {
                "available": True,
                "intent": understanding.intent,
                "lane": "network_log_hunt" if understanding.domain == "log_security" else understanding.domain,
                "entities": list(understanding.entities or []),
                "requested_backends": list(understanding.requested_backends or []),
                "timerange": dict(understanding.timerange or {}),
                "capabilities_required": list(understanding.capabilities_required or []),
                "safety_flags": list(understanding.safety_flags or []),
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    @staticmethod
    def _apply_cross_check(candidate: SOCInterpretation, validation: SOCInterpretationValidationResult, cross_check: Dict[str, Any], analyst_message: str, context: Dict[str, Any]) -> None:
        lowered = str(analyst_message or "").lower()
        if any(token in lowered for token in ("ignore schema", "ignore your", "pretend", "do not ask approval", "disable", "block", "contain", "mark it malicious")):
            for flag in ("prompt_injection_attempt" if "ignore" in lowered or "pretend" in lowered else "destructive_action_requested",):
                if flag not in candidate.safety_flags:
                    candidate.safety_flags.append(flag)
            if any(token in lowered for token in ("disable", "block", "contain")):
                validation.safety_status = "needs_approval"
        if not cross_check.get("available"):
            return
        candidate_values = {(entity.type, entity.value) for entity in candidate.entities}
        for entity in cross_check.get("entities", []) or []:
            etype = entity.get("type")
            value = entity.get("value")
            if etype in {"ip", "domain", "url", "hash", "cve", "email", "user", "host"} and value and (etype, value) not in candidate_values:
                validation.warnings.append("cross_check_missing_entity")
                candidate.entities.append(
                    SOCEntityCandidate(
                        type=etype,
                        value=value,
                        role=entity.get("role") or "observable",
                        source="deterministic_cross_check",
                        confidence=0.75,
                        sanity_status="matched_deterministic_extractor",
                    )
                )
        for backend in cross_check.get("requested_backends", []) or []:
            if backend not in candidate.requested_backends:
                validation.warnings.append("cross_check_missing_backend")
                candidate.requested_backends.append(backend)
        det_timerange = cross_check.get("timerange") or {}
        if det_timerange.get("source") == "analyst_request" and candidate.timerange and candidate.timerange.get("requested") != det_timerange.get("requested"):
            validation.warnings.append("timerange_conflict_deterministic_cross_check")
def extract_compact_interpretation_metadata(result: SOCInterpretationResult) -> Dict[str, Any]:
    interpretation = result.interpretation
    validation = result.validation.to_dict()
    return {
        "interpretation_mode": (interpretation.provenance.get("feature_flag_mode") if interpretation else None),
        "interpretation_status": result.status,
        "interpretation_confidence": interpretation.confidence if interpretation else None,
        "interpretation_source": INTERPRETER_VERSION if interpretation else None,
        "interpretation_repair_attempted": bool(result.repair_metadata.get("attempted")),
        "interpretation_fallback_used": bool(result.fallback_metadata.get("used")),
        "interpretation_validation_warnings": validation.get("warnings", []),
    }
