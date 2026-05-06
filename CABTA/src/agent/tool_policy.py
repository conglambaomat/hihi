"""Central tool policy decisions for AISA capability-bound execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class ToolPolicyDecision:
    """Policy result emitted before a legacy/MCP tool is invoked."""

    allowed: bool
    status: str
    tool_name: str = ""
    capability_id: str = ""
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    approval_required: bool = False
    degraded: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "tool-policy-decision/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ToolPolicyEngine:
    """Conservative centralized policy for capability-to-tool execution.

    This engine is intentionally deterministic. It does not decide verdicts; it
    decides whether an already-bound capability action is safe to execute.
    """

    DEFAULT_ALLOWED_TOOLS = {
        "log.search": {"search_logs"},
        "log.analyze.inline": {"analyze_log_artifact"},
        "email.analyze": {"analyze_email"},
        "email.parse.inline": {"analyze_email"},
        "file.analyze.static": {"analyze_malware"},
        "ioc.enrich": {"investigate_ioc"},
        "ioc.extract": {"extract_iocs"},
        "correlate.findings": {"correlate_findings"},
        "findings.correlate": {"correlate_findings"},
    }

    DANGEROUS_PREFIXES = ("ir.",)

    DEFAULT_SCOPES = {
        "log.search": {"network:siem", "data:logs"},
        "ioc.enrich": {"network:threat_intel"},
        "file.analyze.static": {"filesystem:read"},
        "email.analyze": {"filesystem:read"},
    }

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config = config if isinstance(config, dict) else {}
        policy_cfg = dict((self.config.get("agent", {}) or {}).get("tool_policy", {}) or {})
        self.allowed_scopes = set(policy_cfg.get("allowed_scopes") or [])

    def evaluate(
        self,
        *,
        tool_name: str,
        capability_id: str,
        params: Dict[str, Any] | None = None,
        action: Dict[str, Any] | None = None,
        preflight: Dict[str, Any] | None = None,
        context: Dict[str, Any] | None = None,
    ) -> ToolPolicyDecision:
        params = dict(params or {})
        action = dict(action or {})
        preflight = dict(preflight or {})
        context = dict(context or {})
        capability_id = str(capability_id or action.get("capability_id") or "").strip()
        tool_name = str(tool_name or action.get("legacy_tool_hint") or "").strip()
        reasons: List[str] = []
        warnings: List[str] = []
        approval_required = False

        if not capability_id:
            reasons.append("Capability id is required for investigation tool execution.")
        if not tool_name:
            reasons.append("Resolved tool name is required for execution.")

        if capability_id in self.DEFAULT_ALLOWED_TOOLS and tool_name:
            allowed_tools = set(action.get("allowed_tools") or []) or self.DEFAULT_ALLOWED_TOOLS[capability_id]
            if tool_name not in allowed_tools:
                reasons.append(f"Tool '{tool_name}' is not allowed for capability '{capability_id}'.")

        if capability_id.startswith(self.DANGEROUS_PREFIXES) or bool(action.get("approval_policy", {}).get("approval_required")):
            approval_required = True
            reasons.append("Response or destructive capability requires analyst approval.")

        if preflight and preflight.get("allowed") is False:
            reasons.extend(str(item) for item in preflight.get("blocking_reasons") or ["Preflight denied execution."])
        if preflight and preflight.get("warnings"):
            warnings.extend(str(item) for item in preflight.get("warnings") or [])

        if capability_id == "log.search":
            timerange = str(params.get("timerange") or "").strip().lower()
            if timerange in {"all", "*", "forever"}:
                reasons.append("Unbounded log query timerange is blocked by tool policy.")
            if not params.get("backend"):
                warnings.append("No explicit SIEM/log backend provided; backend wrapper must degrade honestly.")

        if capability_id == "file.analyze.static" and params.get("file_path"):
            file_path = str(params.get("file_path") or "")
            if file_path.startswith("http://") or file_path.startswith("https://"):
                reasons.append("Remote URLs are not valid local file paths for static malware analysis.")

        required_scopes = set(action.get("permission_scopes") or self.DEFAULT_SCOPES.get(capability_id, set()))
        if self.allowed_scopes and not required_scopes.issubset(self.allowed_scopes):
            missing = sorted(required_scopes - self.allowed_scopes)
            reasons.append("Missing allowed permission scopes: " + ", ".join(missing))
        if params.get("url") and str(params.get("url")).startswith(("http://", "https://")) and "network:external" not in self.allowed_scopes and capability_id not in {"ioc.enrich"}:
            reasons.append("External network URL access requires network:external scope.")

        allowed = not reasons and not approval_required
        status = "allowed" if allowed else "approval_required" if approval_required else "blocked"
        return ToolPolicyDecision(
            allowed=allowed,
            status=status,
            tool_name=tool_name,
            capability_id=capability_id,
            reasons=list(dict.fromkeys(reasons)),
            warnings=list(dict.fromkeys(warnings)),
            approval_required=approval_required,
            degraded=bool(preflight.get("degraded")),
            metadata={"context_keys": sorted(context.keys()), "required_scopes": sorted(required_scopes), "allowed_scopes": sorted(self.allowed_scopes)},
        )
