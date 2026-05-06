"""Schema-constrained SOC request interpretation contracts for AISA."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field as dc_field
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "soc-interpretation/v1"

CONVERSATION_ROLES = {"new_task", "follow_up", "clarification_response", "approval_response", "capability_question", "general_chat"}
PRIMARY_INTENTS = {"ioc_triage", "phishing_email_analysis", "malware_file_analysis", "threat_hunt", "log_search", "incident_response", "followup_summary", "config_capability_question", "clarify_request", "general_investigation"}
LANES = {"ioc", "email", "file", "network_log_hunt", "incident_response", "case_follow_up", "config", "general"}
OBJECTIVE_TYPES = {"investigate", "triage", "hunt", "analyze_artifact", "summarize", "explain_capability", "propose_response_action", "clarify"}
PRIORITIES = {"primary", "secondary", "optional", "required", "recommended"}
ENTITY_TYPES = {"ip", "domain", "url", "hash", "cve", "email", "user", "host", "file_path", "artifact_ref", "backend", "case_ref", "unknown"}
ENTITY_ROLES = {"observable", "source_ip", "destination_ip", "account", "asset", "sender", "recipient", "attachment", "sample", "backend", "approval_target", "entity"}
ENTITY_SOURCES = {"user_message", "prior_context", "llm_inference", "deterministic_cross_check", "message", "task_state"}
SANITY_STATUSES = {"unchecked", "matched_deterministic_extractor", "llm_only", "conflict", "invalid"}
NEED_TYPES = {"collect_evidence", "analyze_artifact", "enrich_ioc", "summarize", "explain", "propose_response_action", "request_approval", "ask_clarification"}
MISSING_FIELDS = {"file_path", "uploaded_artifact", "raw_email_text", "email_headers", "backend", "timerange", "ioc_value", "target", "approval", "prior_task", "scope", "other"}
APPROVAL_ACTION_TYPES = {"contain_host", "disable_user", "block_network", "quarantine_file", "isolate_host", "other"}
APPROVAL_TARGET_TYPES = {"host", "user", "ip", "domain", "file", "endpoint", "other"}
CONFIDENCE_LABELS = {"high", "medium", "low"}


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def _clip(value: Any, limit: int = 1000) -> str:
    return str(value or "")[:limit]


def _as_list(value: Any, limit: int) -> List[Any]:
    if not isinstance(value, list):
        return []
    return value[:limit]


@dataclass
class SOCObjectiveCandidate:
    objective_id: str = ""
    objective_type: str = "investigate"
    summary: str = ""
    rationale: str = ""
    priority: str = "primary"
    lane: str = "general"
    requires_fresh_evidence: bool = True
    success_criteria: List[str] = dc_field(default_factory=list)
    forbidden_claims: List[str] = dc_field(default_factory=list)
    confidence: float = 0.0
    source_spans: List[Dict[str, Any]] = dc_field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.objective_id:
            self.objective_id = _stable_id("objcand", self.objective_type, self.summary)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SOCObjectiveCandidate":
        data = dict(payload or {})
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class SOCEntityCandidate:
    entity_id: str = ""
    type: str = "unknown"
    value: str = ""
    normalized_value: str = ""
    role: str = "observable"
    source: str = "user_message"
    source_spans: List[Dict[str, Any]] = dc_field(default_factory=list)
    confidence: float = 0.0
    sanity_status: str = "unchecked"
    notes: List[str] = dc_field(default_factory=list)

    def __post_init__(self) -> None:
        self.value = _clip(self.value, 500).strip()
        if not self.normalized_value:
            self.normalized_value = self.value.lower() if self.type in {"domain", "email", "hash", "url"} else self.value
        if not self.entity_id:
            self.entity_id = _stable_id("ent", self.type, self.normalized_value, self.role)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SOCEntityCandidate":
        data = dict(payload or {})
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class SOCCapabilityNeed:
    capability_id: str = ""
    need_type: str = "collect_evidence"
    priority: str = "required"
    reason: str = ""
    required_inputs: List[str] = dc_field(default_factory=list)
    expected_outputs: List[str] = dc_field(default_factory=list)
    blocking: bool = True
    confidence: float = 0.0
    ontology_status: str = "valid"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SOCCapabilityNeed":
        data = dict(payload or {})
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class SOCMissingInput:
    missing_id: str = ""
    field: str = "other"
    capability_id: str = ""
    reason: str = ""
    blocking: bool = True
    clarification_question: str = ""
    allowed_alternatives: List[str] = dc_field(default_factory=list)
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if not self.missing_id:
            self.missing_id = _stable_id("missing", self.field, self.capability_id, self.reason)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SOCMissingInput":
        data = dict(payload or {})
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class SOCApprovalNeed:
    approval_id: str = ""
    action_type: str = "other"
    capability_id: str = "ir.approval.request"
    target_type: str = "other"
    target: str = ""
    evidence_required: List[str] = dc_field(default_factory=list)
    evidence_refs: List[str] = dc_field(default_factory=list)
    approval_required: bool = True
    execution_allowed: bool = False
    reason: str = ""
    confidence: float = 0.0

    def __post_init__(self) -> None:
        self.approval_required = True
        self.execution_allowed = False
        if not self.approval_id:
            self.approval_id = _stable_id("approval", self.action_type, self.target_type, self.target)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SOCApprovalNeed":
        data = dict(payload or {})
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class SOCInterpretationValidationResult:
    parse_status: str = "valid_json"
    schema_status: str = "valid"
    enum_status: str = "valid"
    capability_status: str = "valid"
    safety_status: str = "safe"
    warnings: List[str] = dc_field(default_factory=list)
    errors: List[str] = dc_field(default_factory=list)
    authoritative_for_verdict: bool = False

    @property
    def valid(self) -> bool:
        return not self.errors and self.schema_status != "invalid" and self.enum_status != "invalid" and self.capability_status != "invalid"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SOCInterpretation:
    schema_version: str = SCHEMA_VERSION
    interpretation_id: str = ""
    raw_request: str = ""
    normalized_request: str = ""
    conversation_role: str = "new_task"
    primary_intent: str = "general_investigation"
    lane: str = "general"
    objectives: List[SOCObjectiveCandidate] = dc_field(default_factory=list)
    entities: List[SOCEntityCandidate] = dc_field(default_factory=list)
    capability_needs: List[SOCCapabilityNeed] = dc_field(default_factory=list)
    missing_inputs: List[SOCMissingInput] = dc_field(default_factory=list)
    approval_needs: List[SOCApprovalNeed] = dc_field(default_factory=list)
    requested_backends: List[str] = dc_field(default_factory=list)
    timerange: Dict[str, Any] = dc_field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = dc_field(default_factory=list)
    output_preferences: List[str] = dc_field(default_factory=list)
    safety_flags: List[str] = dc_field(default_factory=list)
    confidence: float = 0.0
    confidence_label: str = "low"
    provenance: Dict[str, Any] = dc_field(default_factory=dict)
    raw_llm_output: Any = dc_field(default_factory=dict)
    validation: Dict[str, Any] = dc_field(default_factory=dict)
    repair: Dict[str, Any] = dc_field(default_factory=dict)
    fallback: Dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self) -> None:
        self.raw_request = _clip(self.raw_request, 4000)
        if not self.normalized_request:
            self.normalized_request = " ".join(self.raw_request.lower().split())
        if not self.interpretation_id:
            self.interpretation_id = _stable_id("interp", self.raw_request, self.primary_intent, self.lane)
        self.validation.setdefault("authoritative_for_verdict", False)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["objectives"] = [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in self.objectives]
        payload["entities"] = [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in self.entities]
        payload["capability_needs"] = [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in self.capability_needs]
        payload["missing_inputs"] = [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in self.missing_inputs]
        payload["approval_needs"] = [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in self.approval_needs]
        return payload

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SOCInterpretation":
        data = dict(payload or {})
        data["objectives"] = [SOCObjectiveCandidate.from_dict(item) for item in _as_list(data.get("objectives"), 5) if isinstance(item, dict)]
        data["entities"] = [SOCEntityCandidate.from_dict(item) for item in _as_list(data.get("entities"), 32) if isinstance(item, dict)]
        data["capability_needs"] = [SOCCapabilityNeed.from_dict(item) for item in _as_list(data.get("capability_needs"), 16) if isinstance(item, dict)]
        data["missing_inputs"] = [SOCMissingInput.from_dict(item) for item in _as_list(data.get("missing_inputs"), 12) if isinstance(item, dict)]
        data["approval_needs"] = [SOCApprovalNeed.from_dict(item) for item in _as_list(data.get("approval_needs"), 12) if isinstance(item, dict)]
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


def allowed_capability_ids(ontology: Any) -> List[str]:
    if ontology is None:
        return []
    return sorted(str(item.capability_id) for item in ontology.all())


def validate_soc_interpretation(payload: Dict[str, Any], ontology: Any = None, context: Optional[Dict[str, Any]] = None) -> Tuple[Optional[SOCInterpretation], SOCInterpretationValidationResult]:
    result = SOCInterpretationValidationResult()
    if not isinstance(payload, dict):
        result.schema_status = "invalid"
        result.errors.append("payload_not_object")
        return None, result
    required = ["raw_request", "conversation_role", "primary_intent", "lane", "objectives", "entities", "capability_needs", "confidence"]
    for key in required:
        if key not in payload:
            result.errors.append(f"missing_{key}")
    interpretation = SOCInterpretation.from_dict(payload)
    if interpretation.schema_version != SCHEMA_VERSION:
        result.warnings.append("unexpected_schema_version")
    if interpretation.conversation_role not in CONVERSATION_ROLES:
        result.errors.append("invalid_conversation_role")
    if interpretation.primary_intent not in PRIMARY_INTENTS:
        result.errors.append("invalid_primary_intent")
    if interpretation.lane not in LANES:
        result.errors.append("invalid_lane")
    if not isinstance(interpretation.confidence, (int, float)):
        result.errors.append("invalid_confidence")
    elif interpretation.confidence < 0 or interpretation.confidence > 1:
        result.errors.append("invalid_confidence")
    if interpretation.confidence_label not in CONFIDENCE_LABELS:
        result.errors.append("invalid_confidence_label")
    for objective in interpretation.objectives:
        if objective.objective_type not in OBJECTIVE_TYPES:
            result.errors.append("invalid_objective_type")
        if objective.lane not in LANES:
            result.errors.append("invalid_objective_lane")
        if objective.priority not in PRIORITIES:
            result.errors.append("invalid_objective_priority")
    for entity in interpretation.entities:
        if entity.type not in ENTITY_TYPES:
            result.errors.append("invalid_entity_type")
        if entity.role not in ENTITY_ROLES:
            result.warnings.append("unknown_entity_role")
        if entity.source not in ENTITY_SOURCES:
            result.warnings.append("unknown_entity_source")
        if entity.sanity_status not in SANITY_STATUSES:
            result.errors.append("invalid_entity_sanity_status")
    allowed = set(allowed_capability_ids(ontology))
    for need in interpretation.capability_needs:
        if need.need_type not in NEED_TYPES:
            result.errors.append("invalid_need_type")
        if need.priority not in PRIORITIES:
            result.errors.append("invalid_capability_priority")
        if allowed and need.capability_id not in allowed:
            need.ontology_status = "unknown"
            result.errors.append(f"unknown_capability:{need.capability_id}")
    for missing in interpretation.missing_inputs:
        if missing.field not in MISSING_FIELDS:
            result.errors.append("invalid_missing_field")
    for approval in interpretation.approval_needs:
        approval.approval_required = True
        approval.execution_allowed = False
        if approval.action_type not in APPROVAL_ACTION_TYPES:
            result.errors.append("invalid_approval_action_type")
        if approval.target_type not in APPROVAL_TARGET_TYPES:
            result.errors.append("invalid_approval_target_type")
        if approval.execution_allowed:
            result.errors.append("approval_execution_allowed_forbidden")
    if interpretation.approval_needs or any(flag in interpretation.safety_flags for flag in ("prompt_injection_attempt", "destructive_action_requested", "verdict_without_evidence_requested")):
        result.safety_status = "needs_approval" if interpretation.approval_needs else "needs_clarification"
    if result.errors:
        result.schema_status = "invalid" if any(e.startswith("missing_") or e in {"payload_not_object", "invalid_confidence"} for e in result.errors) else result.schema_status
        result.enum_status = "invalid" if any("invalid_" in e for e in result.errors) else result.enum_status
        result.capability_status = "invalid" if any(e.startswith("unknown_capability") for e in result.errors) else result.capability_status
    interpretation.validation = result.to_dict()
    interpretation.validation["authoritative_for_verdict"] = False
    return (interpretation if result.valid else None), result


def compact_for_task_state(interpretation: SOCInterpretation) -> Dict[str, Any]:
    return {
        "schema_version": interpretation.schema_version,
        "interpretation_id": interpretation.interpretation_id,
        "mode": interpretation.provenance.get("feature_flag_mode"),
        "primary_intent": interpretation.primary_intent,
        "lane": interpretation.lane,
        "confidence": interpretation.confidence,
        "confidence_label": interpretation.confidence_label,
        "validation": dict(interpretation.validation or {}),
        "repair": dict(interpretation.repair or {}),
        "fallback": dict(interpretation.fallback or {}),
        "safety_flags": list(interpretation.safety_flags or []),
    }
