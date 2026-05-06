"""Resolve orchestration capabilities to existing AISA tool actions."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Callable, Dict, Optional

from .capability_ontology import CapabilityOntology, ToolContract


@dataclass
class ResolvedCapability:
    capability: str
    selected_tool: Optional[str]
    provider: Optional[str]
    params_template: Dict[str, Any] = field(default_factory=dict)
    availability: str = "unavailable"
    degradation_reason: str = ""
    confidence: float = 0.0
    tool_contract: Optional[ToolContract] = None
    availability_reason: str = ""
    resolution_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = "capability-resolution/v1"
        payload["capability_id"] = self.capability
        payload["resolution_id"] = self.resolution_id or ("res-" + hashlib.sha1((self.capability + str(self.selected_tool) + self.availability).encode()).hexdigest()[:10])
        payload["availability_reason"] = self.availability_reason or ("tool_registered" if self.availability == "available" else self.degradation_reason)
        payload["degradation"] = {"status": "none" if self.availability == "available" else self.availability, "reason": self.degradation_reason}
        payload["legacy_bridge"] = {"action": "use_tool" if self.selected_tool and self.availability == "available" else "degraded_capability", "tool": self.selected_tool}
        payload["tool_contract"] = self.tool_contract.to_dict() if self.tool_contract else None
        return payload


class CapabilityResolver:
    """Conservative resolver from capability IDs to current tool names."""

    def __init__(self, ontology: Optional[CapabilityOntology] = None, get_tool: Optional[Callable[[str], Any]] = None, plugin_registry: Any = None, allow_static_fallback: bool = True):
        self.plugin_registry = plugin_registry
        self.allow_static_fallback = bool(allow_static_fallback)
        if ontology is not None:
            self.ontology = ontology
        elif plugin_registry is not None and getattr(plugin_registry, "ontology", None) is not None:
            self.ontology = plugin_registry.ontology
        else:
            # Use the built-in ontology for standalone/test wiring; production can
            # explicitly fail closed by setting allow_static_fallback=False.
            self.ontology = CapabilityOntology() if self.allow_static_fallback else CapabilityOntology(capabilities=[])
        self.get_tool = get_tool

    def resolve(self, capability: str, objective: Any = None, state: Any = None) -> ResolvedCapability:
        capability_id = str(capability or "").strip()
        contract = self.ontology.get(capability_id)
        if contract is None:
            return ResolvedCapability(
                capability=capability_id,
                selected_tool=None,
                provider=None,
                availability="unknown_capability",
                degradation_reason=f"Capability '{capability_id}' is not registered in the active plugin registry.",
                confidence=0.0,
                availability_reason=f"Capability {capability_id!r} is not registered.",
            )
        for tool_contract in contract.compatible_tools:
            tool_available = self._tool_available(tool_contract.tool_name, state)
            if tool_available:
                return ResolvedCapability(
                    capability=capability_id,
                    selected_tool=tool_contract.tool_name,
                    provider=tool_contract.provider,
                    params_template=self._params_template(capability_id, objective, tool_contract),
                    availability="available",
                    confidence=0.9,
                    tool_contract=tool_contract,
                    availability_reason="tool_registered",
                )
        reason = "No compatible tool is currently registered or available."
        if not contract.compatible_tools:
            reason = "Capability is modeled for planning/audit but has no legacy tool adapter in Phase 2."
        return ResolvedCapability(
            capability=capability_id,
            selected_tool=None,
            provider=None,
            params_template=self._params_template(capability_id, objective, None),
            availability="degraded" if contract.degraded_allowed else "unavailable",
            degradation_reason=reason,
            confidence=0.2 if contract.degraded_allowed else 0.0,
            availability_reason=reason,
        )

    def decision_to_tool_action(self, decision: Dict[str, Any], objective: Any = None, state: Any = None) -> Dict[str, Any]:
        """Bridge a use_capability decision into the legacy use_tool shape."""
        if not isinstance(decision, dict) or decision.get("action") != "use_capability":
            return dict(decision or {})
        capability = str(decision.get("capability") or decision.get("capability_id") or "").strip()
        resolution = self.resolve(capability, objective=objective, state=state)
        params = dict(resolution.params_template)
        params.update(dict(decision.get("params") or {}))
        if resolution.availability != "available" or not resolution.selected_tool:
            return {
                "action": "degraded_capability",
                "capability": capability,
                "capability_id": capability,
                "availability": resolution.availability,
                "degradation_reason": resolution.degradation_reason,
                "params": params,
                "resolution": resolution.to_dict(),
            }
        return {
            "action": "use_tool",
            "tool": resolution.selected_tool,
            "params": params,
            "capability": capability,
            "capability_id": capability,
            "resolution": resolution.to_dict(),
        }

    def _tool_available(self, tool_name: str, state: Any = None) -> bool:
        if self.get_tool is not None:
            try:
                return self.get_tool(tool_name) is not None
            except Exception:
                return False
        tools = getattr(state, "tools", None) or getattr(state, "tool_registry", None)
        if tools is not None and hasattr(tools, "get_tool"):
            try:
                return tools.get_tool(tool_name) is not None
            except Exception:
                return False
        return True

    def _params_template(self, capability: str, objective: Any = None, tool_contract: Optional[ToolContract] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        objective_dict = objective if isinstance(objective, dict) else {}
        if not objective_dict and objective is not None and hasattr(objective, "to_dict"):
            try:
                objective_dict = objective.to_dict()
            except Exception:
                objective_dict = {}
        summary = str(objective_dict.get("summary") or objective_dict.get("analyst_objective") or "").strip()
        timerange = str(objective_dict.get("effective_timerange") or (objective_dict.get("timerange") or {}).get("effective") or "").strip()
        entities = objective_dict.get("entities") if isinstance(objective_dict.get("entities"), list) else []
        first_entity = ""
        first_file_ref = ""
        first_hash = ""
        for item in entities:
            if isinstance(item, dict) and str(item.get("value") or "").strip():
                value = str(item.get("value")).strip()
                entity_type = str(item.get("type") or item.get("kind") or "").strip().lower()
                first_entity = first_entity or value
                if entity_type in {"file", "file_path", "path", "local_path_reference", "artifact"}:
                    first_file_ref = first_file_ref or value
                if entity_type in {"hash", "sha256", "sha1", "md5"}:
                    first_hash = first_hash or value
        for artifact in objective_dict.get("artifacts", []) if isinstance(objective_dict.get("artifacts"), list) else []:
            if not isinstance(artifact, dict):
                continue
            first_file_ref = first_file_ref or str(artifact.get("file_path") or artifact.get("path") or "").strip()
            first_hash = first_hash or str(artifact.get("sha256") or artifact.get("hash") or "").strip()
        if capability == "log.search":
            params.update({"query": summary or first_entity or "security investigation", "timerange": timerange or "24h"})
        elif capability in {"ioc.enrich", "threat_intel.search"}:
            params.update({"ioc": first_entity or summary})
        elif capability == "email.analyze":
            params.update({"email_content": summary})
        elif capability.startswith("file.analyze"):
            if first_file_ref:
                params.update({"file_path": first_file_ref})
            if first_hash:
                params.update({"hash": first_hash})
        elif capability == "ioc.extract":
            params.update({"text": summary})
        else:
            params.update({"objective": summary})
        if tool_contract and tool_contract.supports_timerange and timerange:
            params["timerange"] = timerange
        return params
