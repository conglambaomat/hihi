"""Preflight validation for typed SOC capability actions."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .capability_actions import CapabilityAction
from .parameter_binder import ParameterBindingResult


@dataclass
class PreflightDecision:
    allowed: bool
    status: str
    blocking_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    clarification_required: bool = False
    approval_required: bool = False
    degraded: bool = False
    normalized_params: Dict[str, Any] = field(default_factory=dict)
    progress_event: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "preflight-decision/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PreflightValidator:
    """Block unsafe or under-bound actions before legacy tool execution."""

    def validate(
        self,
        action: CapabilityAction | Dict[str, Any],
        binding: ParameterBindingResult | Dict[str, Any],
        task_state: Any,
        tool_registry: Any = None,
        capability_resolver: Any = None,
    ) -> PreflightDecision:
        action_obj = action if isinstance(action, CapabilityAction) else CapabilityAction.from_dict(action)
        binding_obj = binding if isinstance(binding, ParameterBindingResult) else ParameterBindingResult(**dict(binding or {}))
        params = dict(binding_obj.params or {})
        blockers: List[str] = []
        warnings: List[str] = []
        clarification_required = bool(binding_obj.needs_clarification)
        approval_required = bool(action_obj.approval_policy.get("approval_required")) or action_obj.capability_id.startswith("ir.")
        degraded = False

        if binding_obj.missing_required:
            blockers.append("Missing required typed parameters: " + ", ".join(binding_obj.missing_required))
        if binding_obj.invalid_fields:
            blockers.append("Invalid or leaked scalar parameters: " + ", ".join(binding_obj.invalid_fields))

        capability = action_obj.capability_id
        compiled = getattr(task_state, "compiled_input", {}) or getattr(task_state, "objective_contract", {}).get("compiled_input", {}) if hasattr(getattr(task_state, "objective_contract", {}), "get") else {}
        if capability in {"file.analyze.static", "email.analyze", "email.parse.inline"} and isinstance(compiled, dict) and compiled.get("input_kind") == "soc_alert_text":
            forbidden = ((getattr(task_state, "capability_plan", {}) or {}).get("forbidden_fallbacks", []) if isinstance(getattr(task_state, "capability_plan", {}), dict) else [])
            if capability in forbidden or capability == "file.analyze.static":
                if capability == "file.analyze.static" and not (params.get("file_path") or params.get("hash") or params.get("sha256")):
                    blockers.append("SOC alert text is authoritative log-search input; file analysis requires an explicit file path or hash artifact.")
                    clarification_required = True
                elif capability != "file.analyze.static":
                    blockers.append("SOC alert text forbids legacy email/file fallback routing; use log.search/correlation instead.")
                    clarification_required = True
        if capability == "file.analyze.static":
            if params.get("declared_missing"):
                blockers.append("The sample was declared not uploaded; file analysis is blocked until upload/select file or hash-only triage.")
                clarification_required = True
            file_path = str(params.get("file_path") or "").strip()
            if file_path and not params.get("declared_missing") and not os.path.exists(file_path):
                blockers.append("File path does not exist locally; upload/select the sample or provide a hash.")
                clarification_required = True
            if not file_path and not params.get("hash"):
                clarification_required = True
        elif capability == "email.parse.inline":
            if not (params.get("raw_email_text") or params.get("sender") or params.get("urls")):
                blockers.append("Inline email triage requires raw email text or sender/URL details.")
                clarification_required = True
            if not params.get("headers"):
                warnings.append("Email headers are missing; phishing verdict must state header-authentication limitations.")
        elif capability == "log.search":
            requested_timerange = params.get("requested_timerange") if isinstance(params.get("requested_timerange"), dict) else getattr(task_state, "timerange", {})
            explicit = str((requested_timerange or {}).get("effective") or (requested_timerange or {}).get("value") or (requested_timerange or {}).get("requested") or "").strip()
            if explicit and str(params.get("timerange") or "") != explicit:
                blockers.append("Timerange overwrite detected before log execution.")
            if not params.get("backend"):
                warnings.append("No explicit log backend was provided; execution must use a declared default/demo backend or ask for scope.")
        elif capability == "ioc.enrich":
            if not (params.get("ioc_value") or params.get("ioc")):
                blockers.append("IOC enrichment requires a normalized IOC value.")
                clarification_required = True
        elif capability.startswith("ir."):
            approval_required = True
            if not params.get("target") and capability != "ir.approval.request":
                blockers.append("Response action proposal requires a typed target.")
                clarification_required = True
            blockers.append("Response action is approval-gated and must not execute silently.")

        resolution_dict: Dict[str, Any] = {}
        if capability_resolver is not None and capability not in {"clarification.request", "case.summarize", "task.summarize"} and not capability.startswith("ir."):
            try:
                resolution = capability_resolver.resolve(capability, objective=getattr(task_state, "objective_contract", {}), state=None)
                resolution_dict = resolution.to_dict()
                if resolution.availability not in {"available", "unknown_capability"}:
                    degraded = True
                    warnings.append(resolution.degradation_reason or "Capability is degraded or unavailable.")
            except Exception as exc:
                degraded = True
                warnings.append(f"Capability resolution failed: {exc}")

        allowed = not blockers and not approval_required
        status = "allowed" if allowed else ("approval_required" if approval_required and not clarification_required else "clarification_required" if clarification_required else "blocked")
        event_type = "preflight_allowed" if allowed else status
        progress_event = {
            "event_type": event_type,
            "capability_id": capability,
            "action_id": action_obj.action_id,
            "status": status,
            "blocking_reasons": list(blockers),
            "warnings": list(warnings),
            "resolution": resolution_dict,
        }
        return PreflightDecision(
            allowed=allowed,
            status=status,
            blocking_reasons=list(dict.fromkeys(blockers)),
            warnings=list(dict.fromkeys(warnings)),
            clarification_required=clarification_required,
            approval_required=approval_required,
            degraded=degraded,
            normalized_params=params,
            progress_event=progress_event,
        )
