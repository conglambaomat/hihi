"""Capability execution envelope for AISA agent tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict

from .capability_actions import CapabilityAction, CAPABILITY_TO_LEGACY_TOOL
from .parameter_binder import ParameterBinder
from .preflight_validator import PreflightValidator
from .tool_policy import ToolPolicyEngine


LEGACY_TOOL_TO_CAPABILITY = {
    tool: capability
    for capability, tool in CAPABILITY_TO_LEGACY_TOOL.items()
    if tool
}


@dataclass
class CapabilityExecutionEnvelope:
    """Validated bridge from a capability action to a concrete tool call."""

    allowed: bool
    status: str
    action: Dict[str, Any] = field(default_factory=dict)
    binding: Dict[str, Any] = field(default_factory=dict)
    preflight: Dict[str, Any] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    tool_name: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    capability_id: str = ""
    reason: str = ""
    schema_version: str = "capability-execution-envelope/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CapabilityActionExecutor:
    """Build mandatory typed execution envelopes before legacy tool execution."""

    def __init__(
        self,
        *,
        binder: ParameterBinder | None = None,
        preflight_validator: PreflightValidator | None = None,
        policy_engine: ToolPolicyEngine | None = None,
        capability_resolver: Any = None,
        tool_registry: Any = None,
    ) -> None:
        self.binder = binder or ParameterBinder()
        self.preflight_validator = preflight_validator or PreflightValidator()
        self.policy_engine = policy_engine or ToolPolicyEngine()
        self.capability_resolver = capability_resolver
        self.tool_registry = tool_registry

    def capability_for_tool(self, tool_name: str) -> str:
        return LEGACY_TOOL_TO_CAPABILITY.get(str(tool_name or "").strip(), "")

    def from_legacy_decision(
        self,
        *,
        decision: Dict[str, Any],
        task_state: Any,
        objective_contract: Dict[str, Any] | None = None,
        context: Dict[str, Any] | None = None,
    ) -> CapabilityExecutionEnvelope:
        decision = dict(decision or {})
        tool_name = str(decision.get("tool") or "").strip()
        capability_id = str(decision.get("capability") or decision.get("capability_id") or self.capability_for_tool(tool_name)).strip()
        if not capability_id:
            return CapabilityExecutionEnvelope(
                allowed=False,
                status="blocked",
                tool_name=tool_name,
                params=dict(decision.get("params") or {}),
                reason=f"No capability mapping exists for tool '{tool_name}'.",
            )
        return self.prepare(
            capability_id=capability_id,
            task_state=task_state,
            objective_contract=objective_contract,
            requested_tool=tool_name,
            initial_params=dict(decision.get("params") or {}),
            rationale=str(decision.get("reasoning") or "Legacy use_tool normalized through capability boundary."),
            context=context,
        )

    def prepare(
        self,
        *,
        capability_id: str,
        task_state: Any,
        objective_contract: Dict[str, Any] | None = None,
        requested_tool: str = "",
        initial_params: Dict[str, Any] | None = None,
        rationale: str = "",
        context: Dict[str, Any] | None = None,
    ) -> CapabilityExecutionEnvelope:
        objective_contract = objective_contract if isinstance(objective_contract, dict) else getattr(task_state, "objective_contract", {}) or {}
        action = CapabilityAction(
            task_ref=getattr(task_state, "task_id", ""),
            objective_ref=str(objective_contract.get("contract_id") or ""),
            capability_id=capability_id,
            bound_params=dict(initial_params or {}),
            rationale=rationale or f"Capability {capability_id} execution boundary.",
            legacy_tool_hint=requested_tool or CAPABILITY_TO_LEGACY_TOOL.get(capability_id),
        )
        if requested_tool:
            action.legacy_tool_hint = requested_tool
        binding = self.binder.bind(action, task_state, objective_contract, context or {})
        action.bound_params = dict(binding.params)
        preflight = self.preflight_validator.validate(action, binding, task_state, self.tool_registry, self.capability_resolver)

        resolved_tool = requested_tool or action.legacy_tool_hint or ""
        resolution_dict: Dict[str, Any] = {}
        if self.capability_resolver is not None:
            try:
                resolution = self.capability_resolver.resolve(capability_id, objective=objective_contract, state=None)
                resolution_dict = resolution.to_dict()
                if not resolved_tool:
                    resolved_tool = str(resolution.selected_tool or "")
            except Exception as exc:  # pragma: no cover - defensive audit path
                resolution_dict = {"error": str(exc)}
        preflight_dict = preflight.to_dict()
        if resolution_dict:
            preflight_dict.setdefault("resolution", resolution_dict)

        policy = self.policy_engine.evaluate(
            tool_name=resolved_tool,
            capability_id=capability_id,
            params=preflight.normalized_params,
            action=action.to_dict(),
            preflight=preflight_dict,
            context=context or {},
        )
        allowed = bool(preflight.allowed and policy.allowed and resolved_tool)
        status = "allowed" if allowed else policy.status if policy.status != "allowed" else preflight.status
        reason = "; ".join(policy.reasons or preflight.blocking_reasons or preflight.warnings or [])
        return CapabilityExecutionEnvelope(
            allowed=allowed,
            status=status,
            action=action.to_dict(),
            binding=binding.to_dict(),
            preflight=preflight_dict,
            policy=policy.to_dict(),
            tool_name=resolved_tool,
            params=dict(preflight.normalized_params),
            capability_id=capability_id,
            reason=reason,
        )
