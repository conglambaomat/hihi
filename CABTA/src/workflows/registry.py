"""Markdown-backed workflow registry for the CABTA orchestration plane."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is already used elsewhere
    yaml = None


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)


@dataclass
class WorkflowDefinition:
    workflow_id: str
    name: str
    description: str
    execution_backend: str = "agent"
    playbook_id: Optional[str] = None
    default_agent_profile: Optional[str] = None
    use_case: str = ""
    trigger_examples: List[str] = field(default_factory=list)
    agents: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    optional_tools: List[str] = field(default_factory=list)
    required_mcp_servers: List[str] = field(default_factory=list)
    optional_mcp_servers: List[str] = field(default_factory=list)
    required_features: List[str] = field(default_factory=list)
    approval_mode: str = "inherited"
    headless_ready: bool = False
    source_path: str = ""
    definition_file: str = "WORKFLOW.md"
    definition_kind: str = "workflow"
    body: str = ""
    sections: Dict[str, str] = field(default_factory=dict)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "execution_backend": self.execution_backend,
            "playbook_id": self.playbook_id,
            "default_agent_profile": self.default_agent_profile,
            "agent_count": len(self.agents),
            "agents": list(self.agents),
            "multi_agent": len(self.agents) > 1,
            "required_tools": list(self.required_tools),
            "required_mcp_servers": list(self.required_mcp_servers),
            "required_features": list(self.required_features),
            "approval_mode": self.approval_mode,
            "headless_ready": self.headless_ready,
            "definition_file": self.definition_file,
            "definition_kind": self.definition_kind,
            "trigger_examples": list(self.trigger_examples),
            "capabilities": list(self.capabilities),
        }

    def to_detail_dict(self) -> Dict[str, Any]:
        payload = self.to_summary_dict()
        payload.update({
            "use_case": self.use_case,
            "agents": list(self.agents),
            "tools_used": list(self.tools_used),
            "source_path": self.source_path,
            "body": self.body,
            "sections": deepcopy(self.sections),
        })
        return payload


class WorkflowRegistry:
    """Load lightweight workflow definitions from markdown files."""

    def __init__(self, workflow_root: Optional[str] = None):
        self.workflow_root = Path(workflow_root) if workflow_root else Path(__file__).resolve().parents[2] / "workflows"
        self._workflows: Dict[str, WorkflowDefinition] = {}
        self.load()

    def load(self) -> int:
        self._workflows = {}
        if not self.workflow_root.exists():
            return 0

        count = 0
        candidate_paths = list(sorted(self.workflow_root.glob("*/WORKFLOW.md")))
        for skill_path in sorted(self.workflow_root.glob("*/SKILL.md")):
            if not any(existing.parent == skill_path.parent for existing in candidate_paths):
                candidate_paths.append(skill_path)

        for path in sorted(candidate_paths):
            workflow = self._load_workflow_file(path)
            if workflow:
                self._workflows[workflow.workflow_id] = workflow
                count += 1
        return count

    def list_workflows(self) -> List[Dict[str, Any]]:
        return [
            workflow.to_summary_dict()
            for workflow in sorted(self._workflows.values(), key=lambda item: item.name)
        ]

    def validate_workflow_definition(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a markdown workflow definition/frontmatter contract."""
        issues: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        if not isinstance(definition, dict):
            return {
                "valid": False,
                "issues": [{"level": "error", "message": "Workflow definition must be a mapping/dict"}],
                "warnings": [],
            }

        workflow_id = str(definition.get("id") or definition.get("name") or "").strip()
        name = str(
            definition.get("display-name")
            or definition.get("display_name")
            or definition.get("name")
            or ""
        ).strip()
        execution_backend = str(
            definition.get("execution-backend")
            or definition.get("execution_backend")
            or "agent"
        ).strip().lower()

        if not workflow_id:
            issues.append({"level": "error", "message": "Workflow must declare id or name"})
        if not name:
            issues.append({"level": "error", "message": "Workflow must declare a display name or name"})
        if execution_backend not in {"agent", "playbook"}:
            issues.append(
                {
                    "level": "error",
                    "message": f"Unsupported execution backend '{execution_backend}'",
                }
            )

        playbook_id = definition.get("playbook-id") or definition.get("playbook_id")
        if execution_backend == "playbook" and not playbook_id:
            issues.append(
                {
                    "level": "error",
                    "message": "Playbook-backed workflows must declare playbook-id",
                }
            )
        if execution_backend == "agent" and playbook_id:
            warnings.append(
                {
                    "level": "warning",
                    "message": "Agent-backed workflow declares playbook-id; value will be ignored unless backend is playbook",
                }
            )

        approval_mode = str(
            definition.get("approval-mode")
            or definition.get("approval_mode")
            or "inherited"
        ).strip().lower()
        if approval_mode not in {"inherited", "none", "analyst"}:
            issues.append(
                {
                    "level": "error",
                    "message": f"Unsupported approval mode '{approval_mode}'",
                }
            )

        headless_ready = bool(
            definition.get("headless-ready")
            or definition.get("headless_ready")
            or False
        )

        required_tools = list(definition.get("required-tools") or definition.get("required_tools") or [])
        required_servers = list(
            definition.get("required-mcp-servers") or definition.get("required_mcp_servers") or []
        )
        required_features = list(
            definition.get("required-features") or definition.get("required_features") or []
        )
        agents = list(definition.get("agents") or [])
        capabilities = list(definition.get("capabilities") or [])

        if not required_tools and not required_servers and not required_features:
            warnings.append(
                {
                    "level": "warning",
                    "message": "Workflow declares no required tools, servers, or features",
                }
            )
        if not agents:
            warnings.append(
                {
                    "level": "warning",
                    "message": "Workflow declares no explicit agents/specialists",
                }
            )
        if not capabilities:
            warnings.append(
                {
                    "level": "warning",
                    "message": "Workflow declares no capability tags",
                }
            )

        if headless_ready and approval_mode == "analyst":
            warnings.append(
                {
                    "level": "warning",
                    "message": "Headless-ready workflow still requires analyst approval checkpoints",
                }
            )

        return {
            "valid": not any(item.get("level") == "error" for item in issues),
            "issues": issues,
            "warnings": warnings,
            "execution_backend": execution_backend,
            "approval_mode": approval_mode,
            "headless_ready": headless_ready,
            "requires_playbook": bool(execution_backend == "playbook"),
            "required_tools": required_tools,
            "required_mcp_servers": required_servers,
            "required_features": required_features,
            "dependency_count": len(required_tools) + len(required_servers) + len(required_features),
            "agent_count": len(agents),
            "capability_count": len(capabilities),
        }

    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            return None
        return workflow.to_detail_dict()

    def describe_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            return None

        detail = workflow.to_detail_dict()
        sections = workflow.sections or {}
        validation = self.validate_workflow_definition(
            {
                "id": workflow.workflow_id,
                "name": workflow.name,
                "description": workflow.description,
                "execution_backend": workflow.execution_backend,
                "playbook_id": workflow.playbook_id,
                "agents": list(workflow.agents),
                "capabilities": list(workflow.capabilities),
                "required_tools": list(workflow.required_tools),
                "required_mcp_servers": list(workflow.required_mcp_servers),
                "required_features": list(workflow.required_features),
                "approval_mode": workflow.approval_mode,
                "headless_ready": workflow.headless_ready,
            }
        )

        detail["validation"] = validation
        evidence_contract = {
            "required": True,
            "require_typed_observations": False,
            "require_triage_contract_evidence": False,
            "minimum_required_fields": 0,
        }
        workflow_id = str(workflow.workflow_id or "").strip().lower()
        if workflow_id in {"threat-hunt", "incident-response"}:
            evidence_contract.update(
                {
                    "require_typed_observations": True,
                    "require_triage_contract_evidence": True,
                    "minimum_required_fields": 2,
                }
            )

        detail["execution_contract"] = {
            "multi_agent": len(workflow.agents) > 1,
            "headless_ready": workflow.headless_ready,
            "approval_mode": workflow.approval_mode,
            "requires_playbook": bool(workflow.execution_backend.lower() == "playbook"),
            "supports_headless_execution": bool(workflow.headless_ready and workflow.approval_mode not in {"analyst", "analyst-gated"}),
            "dependency_count": validation.get("dependency_count", 0),
            "required_dependencies": {
                "tools": list(workflow.required_tools),
                "mcp_servers": list(workflow.required_mcp_servers),
                "features": list(workflow.required_features),
            },
            "fallback_paths": self._extract_bullets(sections.get("fallback_paths", ""), limit=6),
            "stop_conditions": self._extract_bullets(sections.get("stop_conditions", ""), limit=6),
            "plan_contract": {
                "required": True,
                "planner": "InvestigationPlanner",
                "pivot_signals_supported": True,
                "resume_signals_supported": True,
            },
            "evidence_contract": evidence_contract,
            "governance_contract": {
                "contract_version": "governance-contract/v2",
                "deterministic_verdict_owner": "CABTA deterministic core",
                "decision_logging_supported": True,
                "feedback_logging_supported": True,
                "approvals_required": workflow.approval_mode in {"analyst", "analyst-gated"},
            },
        }
        return detail

    def build_goal(
        self,
        workflow_id: str,
        goal: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> str:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        lines = [
            f"Workflow: {workflow.name}",
            f"Use case: {workflow.use_case or workflow.description}",
            "Execution policy: gather evidence with CABTA tools, analyzers, and integrations before drawing conclusions.",
        ]
        if workflow.default_agent_profile:
            lines.append(f"Specialist profile: {workflow.default_agent_profile}")
        sections = workflow.sections or {}
        operating_model = sections.get("operating_model")
        if operating_model:
            lines.append("Operating model:")
            for bullet in self._extract_bullets(operating_model, limit=4):
                lines.append(f"- {bullet}")
        phase_sequence = sections.get("phase_sequence") or sections.get("phases")
        if phase_sequence:
            lines.append("Phase sequence:")
            for bullet in self._extract_bullets(phase_sequence, limit=5):
                lines.append(f"- {bullet}")
        if goal:
            lines.append(f"Operator goal: {goal}")
        if params:
            lines.append(f"Workflow inputs: {params}")
        return "\n".join(lines)

    def _load_workflow_file(self, path: Path) -> Optional[WorkflowDefinition]:
        raw = path.read_text(encoding="utf-8")
        metadata, body = self._parse_frontmatter(raw)
        if metadata is None:
            return None

        workflow_id = (
            str(metadata.get("id") or metadata.get("name") or path.parent.name)
            .strip()
            .lower()
            .replace(" ", "-")
        )
        sections = self._parse_sections(body)
        return WorkflowDefinition(
            workflow_id=workflow_id,
            name=str(metadata.get("display-name") or metadata.get("display_name") or metadata.get("name") or workflow_id),
            description=str(metadata.get("description") or "").strip(),
            execution_backend=str(metadata.get("execution-backend") or metadata.get("execution_backend") or "agent"),
            playbook_id=metadata.get("playbook-id") or metadata.get("playbook_id"),
            default_agent_profile=metadata.get("default-agent-profile") or metadata.get("default_agent_profile"),
            use_case=str(metadata.get("use-case") or metadata.get("use_case") or "").strip(),
            trigger_examples=list(metadata.get("trigger-examples") or metadata.get("trigger_examples") or []),
            agents=list(metadata.get("agents") or []),
            tools_used=list(metadata.get("tools-used") or metadata.get("tools_used") or []),
            capabilities=list(metadata.get("capabilities") or []),
            required_tools=list(metadata.get("required-tools") or metadata.get("required_tools") or []),
            optional_tools=list(metadata.get("optional-tools") or metadata.get("optional_tools") or []),
            required_mcp_servers=list(metadata.get("required-mcp-servers") or metadata.get("required_mcp_servers") or []),
            optional_mcp_servers=list(metadata.get("optional-mcp-servers") or metadata.get("optional_mcp_servers") or []),
            required_features=list(metadata.get("required-features") or metadata.get("required_features") or []),
            approval_mode=str(metadata.get("approval-mode") or metadata.get("approval_mode") or "inherited"),
            headless_ready=bool(metadata.get("headless-ready") or metadata.get("headless_ready") or False),
            source_path=str(path),
            definition_file=path.name,
            definition_kind="skill" if path.name.upper() == "SKILL.MD" else "workflow",
            body=body.strip(),
            sections=sections,
        )

    def _parse_frontmatter(self, raw: str) -> Tuple[Optional[Dict[str, Any]], str]:
        match = _FRONTMATTER_RE.match(raw)
        if not match or yaml is None:
            return None, raw
        metadata = yaml.safe_load(match.group(1)) or {}
        body = match.group(2) or ""
        if not isinstance(metadata, dict):
            return None, body
        return metadata, body

    @staticmethod
    def _parse_sections(body: str) -> Dict[str, str]:
        sections: Dict[str, str] = {}
        current_key = "overview"
        buffer: List[str] = []

        def _flush() -> None:
            text = "\n".join(buffer).strip()
            if text:
                sections[current_key] = text

        for line in body.splitlines():
            if line.startswith("## "):
                _flush()
                current_key = (
                    line[3:].strip().lower().replace(" ", "_").replace("/", "_")
                )
                buffer = []
                continue
            buffer.append(line)
        _flush()
        return sections

    @staticmethod
    def _extract_bullets(section_text: str, limit: int = 5) -> List[str]:
        bullets: List[str] = []
        numbered = 0
        for raw_line in section_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("- "):
                bullets.append(line[2:].strip())
            elif re.match(r"^\d+\.\s+", line):
                bullets.append(re.sub(r"^\d+\.\s+", "", line))
            elif not bullets:
                bullets.append(line)
            if len(bullets) >= limit:
                break
            numbered += 1
        return bullets[:limit]
