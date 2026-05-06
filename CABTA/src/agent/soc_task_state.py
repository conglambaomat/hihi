"""Canonical SOC task state for AISA natural-chat orchestration."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


@dataclass
class SOCTaskState:
    """Additive canonical state for one SOC natural-chat task or follow-up."""

    schema_version: str = "soc-task-state/v1"
    task_id: str = ""
    session_id: str = ""
    parent_task_id: Optional[str] = None
    raw_request: str = ""
    normalized_request: str = ""
    conversation_role: str = "new_task"
    lane: str = "generic"
    intent: str = "investigation"
    analyst_objective: str = ""
    entities: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    requested_backends: List[str] = field(default_factory=list)
    timerange: Dict[str, Any] = field(default_factory=dict)
    required_capabilities: List[str] = field(default_factory=list)
    compiled_input: Dict[str, Any] = field(default_factory=dict)
    capability_plan: Dict[str, Any] = field(default_factory=dict)
    log_artifact_analysis: Dict[str, Any] = field(default_factory=dict)
    structured_verdict: Dict[str, Any] = field(default_factory=dict)
    objective_contract: Dict[str, Any] = field(default_factory=dict)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    pending_clarifications: List[Dict[str, Any]] = field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    reflection: Dict[str, Any] = field(default_factory=dict)
    final_answer_gate: Dict[str, Any] = field(default_factory=dict)
    progress_events: List[Dict[str, Any]] = field(default_factory=list)
    investigation_dag: Dict[str, Any] = field(default_factory=dict)
    field_sources: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        if not self.task_id:
            self.task_id = _stable_id("soc-task", self.session_id, self.raw_request, self.created_at)
        if not self.normalized_request:
            self.normalized_request = re.sub(r"\s+", " ", str(self.raw_request or "").strip()).lower()
        if not self.analyst_objective:
            self.analyst_objective = str(self.raw_request or "").strip()

    def add_entity(self, entity_type: str, value: str, *, source: str = "message", confidence: float = 0.85, role: str = "observable", **extra: Any) -> None:
        value = str(value or "").strip()
        if not value:
            return
        if any(item.get("type") == entity_type and item.get("value") == value for item in self.entities):
            return
        self.entities.append({"type": entity_type, "value": value, "source": source, "confidence": confidence, "role": role, **extra})
        self.field_sources.setdefault("entities", []).append({"type": entity_type, "value": value, "source": source, "confidence": confidence})
        self.updated_at = _now_iso()

    def add_artifact(self, artifact_type: str, *, source: str = "message", confidence: float = 0.85, **fields: Any) -> Dict[str, Any]:
        artifact = {
            "artifact_id": fields.pop("artifact_id", _stable_id("artifact", self.task_id, artifact_type, fields)),
            "type": artifact_type,
            "source": source,
            "confidence": confidence,
            **fields,
        }
        self.artifacts.append(artifact)
        self.field_sources.setdefault("artifacts", []).append({"artifact_id": artifact["artifact_id"], "source": source, "confidence": confidence})
        self.updated_at = _now_iso()
        return artifact

    def add_progress(self, event_type: str, **fields: Any) -> Dict[str, Any]:
        event = {"event_type": event_type, "timestamp": _now_iso(), **fields}
        self.progress_events.append(event)
        self.progress_events = self.progress_events[-50:]
        self.updated_at = _now_iso()
        return event

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Optional[Dict[str, Any]]) -> "SOCTaskState":
        data = dict(payload or {})
        valid = set(cls.__dataclass_fields__.keys())
        return cls(**{key: value for key, value in data.items() if key in valid})

    @classmethod
    def from_legacy_reasoning_state(cls, reasoning_state: Optional[Dict[str, Any]], *, session_id: str = "", raw_request: str = "") -> "SOCTaskState":
        reasoning_state = reasoning_state if isinstance(reasoning_state, dict) else {}
        existing = reasoning_state.get("soc_task_state")
        if isinstance(existing, dict):
            restored = cls.from_dict(existing)
            if session_id and not restored.session_id:
                restored.session_id = session_id
            return restored
        objective = reasoning_state.get("objective_contract", {}) if isinstance(reasoning_state.get("objective_contract"), dict) else {}
        return cls(
            session_id=session_id,
            raw_request=raw_request or str(objective.get("analyst_objective") or objective.get("summary") or ""),
            lane=str(objective.get("lane") or "generic"),
            intent=str(objective.get("objective_type") or "investigation"),
            analyst_objective=str(objective.get("analyst_objective") or objective.get("summary") or raw_request or ""),
            entities=list(objective.get("entities") or []),
            requested_backends=list(objective.get("requested_backends") or []),
            timerange=dict(objective.get("timerange") or {}),
            required_capabilities=list(objective.get("capabilities_required") or reasoning_state.get("capabilities_required") or []),
            objective_contract=dict(objective),
        )
