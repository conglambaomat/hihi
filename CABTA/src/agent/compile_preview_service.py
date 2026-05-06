"""No-side-effect compile and plan preview service for SOC chat input."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from .capability_plan import CapabilityPlanBuilder
from .investigation_dag import InvestigationDAGBuilder
from .soc_task_state import SOCTaskState
from .universal_input_compiler import UniversalInputCompiler


@dataclass
class SOCTaskContract:
    schema_version: str = "soc-task-contract/v1"
    compiled_input: Dict[str, Any] = field(default_factory=dict)
    task_state: Dict[str, Any] = field(default_factory=dict)
    objective_contract: Dict[str, Any] = field(default_factory=dict)
    capability_plan: Dict[str, Any] = field(default_factory=dict)
    investigation_dag: Dict[str, Any] = field(default_factory=dict)
    missing_inputs: List[Dict[str, Any]] = field(default_factory=list)
    policy_summary: Dict[str, Any] = field(default_factory=dict)
    execution_readiness: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CompilePreviewService:
    """Compile input and build capability plan without starting a session."""

    def __init__(self, compiler: UniversalInputCompiler | None = None, plan_builder: CapabilityPlanBuilder | None = None, dag_builder: InvestigationDAGBuilder | None = None) -> None:
        self.compiler = compiler or UniversalInputCompiler()
        self.plan_builder = plan_builder or CapabilityPlanBuilder()
        self.dag_builder = dag_builder or InvestigationDAGBuilder()

    def compile_and_plan(self, raw_input: str, metadata: Dict[str, Any] | None = None, *, execute: bool = False) -> SOCTaskContract:
        metadata = dict(metadata or {})
        compiled = self.compiler.compile(raw_input, metadata)
        task = SOCTaskState(session_id=str(metadata.get("session_id") or "preview"), raw_request=raw_input)
        task = self.compiler.apply_to_task_state(task, compiled)
        plan = self.plan_builder.build(task, task.objective_contract)
        task.capability_plan = plan.to_dict()
        dag = self.dag_builder.build(task, task.objective_contract, plan.to_dict())
        task.investigation_dag = dag.to_dict()
        clarifications = list(compiled.clarifications or []) + list(task.pending_clarifications or [])
        blockers = []
        if clarifications:
            blockers.append("clarification_required")
        readiness = {
            "ready": not blockers,
            "execute_requested": bool(execute),
            "blockers": blockers,
            "side_effects": "none_preview_only",
        }
        policy_summary = {
            "structured_verdict_only": True,
            "requires_capability_boundary": True,
            "dangerous_actions_require_approval": True,
            "preview_is_not_evidence": True,
        }
        return SOCTaskContract(
            compiled_input=compiled.to_dict(),
            task_state=task.to_dict(),
            objective_contract=task.objective_contract,
            capability_plan=plan.to_dict(),
            investigation_dag=dag.to_dict(),
            missing_inputs=clarifications,
            policy_summary=policy_summary,
            execution_readiness=readiness,
        )
