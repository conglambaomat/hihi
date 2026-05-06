"""Typed append-only agent events for audit and UI streams."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_SECRET_KEYS = ("key", "token", "secret", "password", "authorization")


@dataclass
class AgentEvent:
    event_id: str
    session_id: str
    event_type: str
    timestamp: str
    payload: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    case_id: Optional[str] = None
    task_id: Optional[str] = None
    dag_node_id: Optional[str] = None
    refs: List[Dict[str, Any]] = field(default_factory=list)
    authoritative: bool = False
    schema_version: str = "agent-event/v1"

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        case_id: Optional[str] = None,
        task_id: Optional[str] = None,
        dag_node_id: Optional[str] = None,
        refs: Optional[List[Dict[str, Any]]] = None,
        authoritative: bool = False,
    ) -> "AgentEvent":
        timestamp = datetime.now(timezone.utc).isoformat()
        seed = f"{session_id}:{event_type}:{timestamp}:{len(refs or [])}"
        return cls(
            event_id="evt-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12],
            session_id=session_id,
            event_type=event_type,
            timestamp=timestamp,
            payload=sanitize_event_payload(payload or {}),
            severity=severity,
            case_id=case_id,
            task_id=task_id,
            dag_node_id=dag_node_id,
            refs=refs or [],
            authoritative=authoritative,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sanitize_event_payload(value: Any, *, max_text: int = 2000) -> Any:
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if any(secret in str(key).lower() for secret in _SECRET_KEYS):
                clean[key] = "[redacted]"
            else:
                clean[key] = sanitize_event_payload(item, max_text=max_text)
        return clean
    if isinstance(value, list):
        return [sanitize_event_payload(item, max_text=max_text) for item in value[:50]]
    if isinstance(value, str) and len(value) > max_text:
        return value[:max_text] + "...[truncated]"
    return value
