"""SOC ontology plugin registry with deterministic lifecycle management."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol

from .capability_ontology import CapabilityContract, CapabilityOntology, ToolContract, default_capability_contracts


class CapabilityPlugin(Protocol):
    plugin_id: str
    version: str
    capabilities: List[CapabilityContract]


@dataclass
class PluginStatus:
    plugin_id: str
    version: str
    state: str
    capabilities: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    dependencies: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PluginValidationError(ValueError):
    pass


@dataclass
class BuiltinCapabilityPlugin:
    plugin_id: str = "aisa.builtin.capabilities"
    version: str = "1.0.0"
    capabilities: List[CapabilityContract] = field(default_factory=default_capability_contracts)


class CapabilityPluginRegistry:
    """Register, validate, start, stop, and unload capability ontology plugins."""

    _SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?$")

    def __init__(self, ontology: Optional[CapabilityOntology] = None, *, isolate_errors: bool = True) -> None:
        self.ontology = ontology or CapabilityOntology(capabilities=[])
        self.isolate_errors = isolate_errors
        self._plugins: Dict[str, Any] = {}
        self._statuses: Dict[str, PluginStatus] = {}

    def discover(self, plugins: Iterable[Any]) -> List[PluginStatus]:
        statuses = []
        for plugin in sorted(list(plugins), key=lambda p: (str(getattr(p, "plugin_id", "")), str(getattr(p, "version", "")))):
            statuses.append(self.register(plugin))
        return statuses

    def register(self, plugin: Any) -> PluginStatus:
        plugin_id = str(getattr(plugin, "plugin_id", "") or "").strip()
        version = str(getattr(plugin, "version", "") or "").strip()
        try:
            self._validate_plugin(plugin)
            self._check_dependencies(plugin)
            self._plugins[plugin_id] = plugin
            status = PluginStatus(plugin_id, version, "registered", [c.capability_id for c in plugin.capabilities], dependencies=dict(getattr(plugin, "dependencies", {}) or {}))
            self._statuses[plugin_id] = status
            for capability in sorted(plugin.capabilities, key=lambda c: c.capability_id):
                self.ontology.register_capability(capability)
            return status
        except Exception as exc:
            status = PluginStatus(plugin_id or "<invalid>", version, "rejected", errors=[str(exc)])
            self._statuses[status.plugin_id] = status
            if self.isolate_errors:
                return status
            raise

    def initialize_all(self) -> None:
        for plugin_id in self._ordered_ids():
            self._call_hook(plugin_id, "initialize", target_state="initialized")

    def start_all(self) -> None:
        for plugin_id in self._ordered_ids():
            self._call_hook(plugin_id, "start", target_state="running")

    def stop_all(self) -> None:
        for plugin_id in reversed(self._ordered_ids()):
            self._call_hook(plugin_id, "stop", target_state="stopped")

    def unload(self, plugin_id: str) -> PluginStatus:
        plugin_id = str(plugin_id or "").strip()
        self._call_hook(plugin_id, "unload", target_state="unloaded")
        self._plugins.pop(plugin_id, None)
        return self._statuses[plugin_id]

    @classmethod
    def bootstrap_builtin(cls, *, isolate_errors: bool = True) -> "CapabilityPluginRegistry":
        registry = cls(CapabilityOntology(capabilities=[]), isolate_errors=isolate_errors)
        registry.register(BuiltinCapabilityPlugin())
        registry.initialize_all()
        registry.start_all()
        return registry

    def status(self) -> Dict[str, Any]:
        items = [self._statuses[k].to_dict() for k in sorted(self._statuses)]
        unhealthy = [item for item in items if item["state"] in {"rejected", "failed"}]
        return {"schema_version": "capability-plugin-registry/v1", "healthy": not unhealthy, "plugin_count": len(self._plugins), "plugins": items}

    def export_status(self, path: str | Path) -> Dict[str, Any]:
        payload = self.status()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return payload

    def load_status_snapshot(self, path: str | Path) -> Dict[str, Any]:
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        for item in payload.get("plugins", []) if isinstance(payload, dict) else []:
            if isinstance(item, dict) and item.get("plugin_id"):
                self._statuses[str(item["plugin_id"])] = PluginStatus(**{k: item.get(k) for k in PluginStatus.__dataclass_fields__})
        return self.status()

    def _ordered_ids(self) -> List[str]:
        return sorted(self._plugins.keys(), key=lambda pid: (pid, str(getattr(self._plugins[pid], "version", ""))))

    def _call_hook(self, plugin_id: str, hook: str, *, target_state: str) -> None:
        plugin = self._plugins.get(plugin_id)
        if plugin is None:
            return
        status = self._statuses[plugin_id]
        try:
            fn = getattr(plugin, hook, None)
            if callable(fn):
                fn(self.ontology)
            status.state = target_state
        except Exception as exc:
            status.state = "failed"
            status.errors.append(f"{hook} failed: {exc}")
            if not self.isolate_errors:
                raise

    def _validate_plugin(self, plugin: Any) -> None:
        plugin_id = str(getattr(plugin, "plugin_id", "") or "").strip()
        version = str(getattr(plugin, "version", "") or "").strip()
        if not plugin_id:
            raise PluginValidationError("plugin_id is required")
        if not self._SEMVER_RE.match(version):
            raise PluginValidationError(f"plugin {plugin_id} version must be semantic version MAJOR.MINOR.PATCH")
        capabilities = getattr(plugin, "capabilities", None)
        if not isinstance(capabilities, list) or not capabilities:
            raise PluginValidationError(f"plugin {plugin_id} must declare at least one capability")
        for capability in capabilities:
            if not isinstance(capability, CapabilityContract):
                raise PluginValidationError(f"plugin {plugin_id} capability is not a CapabilityContract")
            if not capability.capability_id or not capability.output_facets:
                raise PluginValidationError(f"capability {capability.capability_id!r} must include id and output facets")
            for tool in capability.compatible_tools:
                if not isinstance(tool, ToolContract) or tool.capability != capability.capability_id:
                    raise PluginValidationError(f"tool contract for {capability.capability_id} is invalid")

    def _check_dependencies(self, plugin: Any) -> None:
        dependencies = dict(getattr(plugin, "dependencies", {}) or {})
        for dep_id, requirement in dependencies.items():
            existing = self._statuses.get(str(dep_id))
            if existing is None or existing.state == "rejected":
                raise PluginValidationError(f"dependency {dep_id} is not registered")
            if str(requirement).startswith(">=") and self._version_tuple(existing.version) < self._version_tuple(str(requirement)[2:]):
                raise PluginValidationError(f"dependency {dep_id} version {existing.version} does not satisfy {requirement}")

    def _version_tuple(self, version: str) -> tuple[int, int, int]:
        match = self._SEMVER_RE.match(str(version or ""))
        if not match:
            return (0, 0, 0)
        return tuple(int(match.group(i)) for i in range(1, 4))


__all__ = ["CapabilityPluginRegistry", "PluginStatus", "PluginValidationError", "BuiltinCapabilityPlugin"]
