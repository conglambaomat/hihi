"""Context ledger helpers for AISA model-call auditability."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .context_pack import AUTHORITY_POLICY, utc_now_iso


@dataclass
class ContextLedger:
    """Compact audit record for selected and dropped prompt context."""

    ledger_id: str
    session_id: str
    step_number: int
    objective: str
    model: str = ""
    prompt_mode: str = ""
    token_estimate: Dict[str, Any] = field(default_factory=dict)
    included: List[Dict[str, Any]] = field(default_factory=list)
    excluded: List[Dict[str, Any]] = field(default_factory=list)
    compression_actions: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    authority_policy: str = AUTHORITY_POLICY
    created_at: str = field(default_factory=utc_now_iso)
    schema_version: str = "context-ledger/v1"
    model_call_id: str = ""
    context_package_ref: str = ""
    visible_limitations: List[str] = field(default_factory=list)
    do_not_claim_constraints: List[str] = field(default_factory=list)
    omitted_evidence_refs: List[str] = field(default_factory=list)

    def add_included(self, item: Dict[str, Any], *, reason: str = "selected") -> None:
        self.included.append(self._summarize_item(item, reason=reason))
        self._extend_refs(item)

    def add_excluded(self, item: Dict[str, Any], *, reason: str = "excluded") -> None:
        self.excluded.append(self._summarize_item(item, reason=reason))

    def add_compression_action(
        self,
        action: str,
        *,
        item_id: str = "",
        reason: str = "",
        before_tokens: int = 0,
        after_tokens: int = 0,
        details: Dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "action": str(action),
            "item_id": str(item_id),
            "reason": str(reason),
            "before_tokens": int(before_tokens or 0),
            "after_tokens": int(after_tokens or 0),
            "authoritative_for_verdict": False,
        }
        if isinstance(details, dict):
            payload["details"] = details
        self.compression_actions.append(payload)

    def _extend_refs(self, item: Dict[str, Any]) -> None:
        refs = item.get("evidence_refs") or item.get("source_refs") or []
        for ref in refs if isinstance(refs, list) else []:
            if isinstance(ref, dict):
                self.evidence_refs.append(ref)
        self.evidence_refs = self._dedupe_refs(self.evidence_refs)[-60:]

    @staticmethod
    def _summarize_item(item: Dict[str, Any], *, reason: str) -> Dict[str, Any]:
        payload = item if isinstance(item, dict) else {}
        return {
            "item_id": payload.get("block_id") or payload.get("brief_id") or payload.get("id") or payload.get("item_id"),
            "kind": payload.get("kind") or payload.get("type") or payload.get("section") or "context_item",
            "section": payload.get("section"),
            "authority": payload.get("authority") or "agentic_explanation",
            "authoritative_for_verdict": bool(payload.get("authoritative_for_verdict", False)),
            "reason": str(reason or payload.get("reason") or ""),
            "score": payload.get("score"),
            "token_estimate": int(payload.get("token_estimate") or 0),
        }

    @staticmethod
    def _dedupe_refs(refs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out: List[Dict[str, Any]] = []
        for ref in refs:
            key = (
                str(ref.get("session_id") or ""),
                str(ref.get("step_number") or ""),
                str(ref.get("finding_index") or ""),
                str(ref.get("tool_name") or ""),
                str(ref.get("observation_id") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(ref)
        return out

    def to_dict(self, *, max_items: int = 120) -> Dict[str, Any]:
        max_items = max(1, int(max_items or 120))
        return {
            "schema_version": self.schema_version,
            "ledger_id": self.ledger_id,
            "model_call_id": self.model_call_id or f"call-{self.session_id}-{self.step_number}",
            "context_package_ref": self.context_package_ref,
            "session_id": self.session_id,
            "step_number": self.step_number,
            "objective": self.objective,
            "model": self.model,
            "prompt_mode": self.prompt_mode,
            "token_estimate": dict(self.token_estimate or {}),
            "included": list(self.included)[-max_items:],
            "excluded": list(self.excluded)[-max_items:],
            "compression_actions": list(self.compression_actions)[-max_items:],
            "evidence_refs": self._dedupe_refs(list(self.evidence_refs))[-max_items:],
            "visible_evidence_refs": self._dedupe_refs(list(self.evidence_refs))[-max_items:],
            "visible_limitations": list(self.visible_limitations),
            "do_not_claim_constraints": list(self.do_not_claim_constraints),
            "omitted_evidence_refs": list(self.omitted_evidence_refs)[-max_items:],
            "authority_policy": self.authority_policy,
            "created_at": self.created_at,
            "authoritative_for_verdict": False,
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "schema_version": "context-ledger-summary/v1",
            "ledger_id": self.ledger_id,
            "model_call_id": self.model_call_id or f"call-{self.session_id}-{self.step_number}",
            "context_package_ref": self.context_package_ref,
            "session_id": self.session_id,
            "step_number": self.step_number,
            "objective": self.objective,
            "model": self.model,
            "prompt_mode": self.prompt_mode,
            "included_count": len(self.included),
            "excluded_count": len(self.excluded),
            "compression_action_count": len(self.compression_actions),
            "evidence_ref_count": len(self._dedupe_refs(list(self.evidence_refs))),
            "authority_policy": self.authority_policy,
            "authoritative_for_verdict": False,
            "created_at": self.created_at,
        }


def append_capped_ledger(history: Any, ledger_summary: Dict[str, Any], *, max_items: int = 12) -> List[Dict[str, Any]]:
    items = [item for item in (history or []) if isinstance(item, dict)] if isinstance(history, list) else []
    items.append(dict(ledger_summary or {}))
    return items[-max(1, int(max_items or 12)):]
