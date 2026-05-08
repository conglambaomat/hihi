"""Adaptive investigation DAG controller and mutation contracts."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .investigation_dag import InvestigationDAG

ADAPTIVE_DAG_TRIGGERS = {
    "coverage_gap",
    "query_empty",
    "query_partial",
    "manual_required",
    "tool_failure",
    "policy_block",
    "hypothesis_new",
    "final_gate_blocked",
    "analyst_follow_up",
    "model_led_planner",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


@dataclass
class AdaptiveDAGPolicy:
    max_mutations: int = 24
    allowed_triggers: List[str] = field(default_factory=lambda: sorted(ADAPTIVE_DAG_TRIGGERS))
    require_strict_boundary: bool = True
    auto_apply: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdaptiveDAGTrigger:
    trigger_type: str
    reason: str = ""
    source: str = "runtime"
    evidence: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdaptiveDAGProposal:
    proposal_id: str
    trigger: Dict[str, Any]
    operation: str = "append_node"
    node: Dict[str, Any] = field(default_factory=dict)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    status: str = "proposed"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdaptiveDAGMutation:
    mutation_id: str
    proposal_id: str
    trigger: Dict[str, Any]
    operation: str
    node: Dict[str, Any] = field(default_factory=dict)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    status: str = "applied"
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdaptiveDAGController:
    """Converts runtime gaps/failures into auditable DAG mutations."""

    def __init__(self, policy: Optional[AdaptiveDAGPolicy | Dict[str, Any]] = None) -> None:
        if isinstance(policy, AdaptiveDAGPolicy):
            self.policy = policy
        elif isinstance(policy, dict):
            self.policy = AdaptiveDAGPolicy(**{k: v for k, v in policy.items() if k in AdaptiveDAGPolicy.__dataclass_fields__})
        else:
            self.policy = AdaptiveDAGPolicy()

    def evaluate(self, dag: InvestigationDAG | Dict[str, Any], trigger: AdaptiveDAGTrigger | Dict[str, Any]) -> Optional[AdaptiveDAGProposal]:
        dag_obj = dag if isinstance(dag, InvestigationDAG) else InvestigationDAG.from_dict(dag)
        trigger_obj = trigger if isinstance(trigger, AdaptiveDAGTrigger) else AdaptiveDAGTrigger(**{k: v for k, v in dict(trigger or {}).items() if k in AdaptiveDAGTrigger.__dataclass_fields__})
        if trigger_obj.trigger_type not in self.policy.allowed_triggers:
            return None
        if len(dag_obj.mutation_ledger or []) >= self.policy.max_mutations:
            return None
        node = self._node_for_trigger(dag_obj, trigger_obj)
        proposal_id = _stable_id("proposal", dag_obj.dag_id, trigger_obj.trigger_type, trigger_obj.reason, len(dag_obj.mutation_ledger))
        return AdaptiveDAGProposal(
            proposal_id=proposal_id,
            trigger=trigger_obj.to_dict(),
            node=node,
            rationale=trigger_obj.reason or f"Adaptive DAG response to {trigger_obj.trigger_type}",
        )

    def apply(self, dag: InvestigationDAG | Dict[str, Any], proposal: AdaptiveDAGProposal | Dict[str, Any]) -> InvestigationDAG:
        dag_obj = dag if isinstance(dag, InvestigationDAG) else InvestigationDAG.from_dict(dag)
        proposal_payload = proposal.to_dict() if hasattr(proposal, "to_dict") else dict(proposal or {})
        mutation = AdaptiveDAGMutation(
            mutation_id=_stable_id("mut", dag_obj.dag_id, proposal_payload.get("proposal_id"), len(dag_obj.mutation_ledger)),
            proposal_id=str(proposal_payload.get("proposal_id") or ""),
            trigger=dict(proposal_payload.get("trigger") or {}),
            operation=str(proposal_payload.get("operation") or "append_node"),
            node=dict(proposal_payload.get("node") or {}),
            edges=list(proposal_payload.get("edges") or []),
            rationale=str(proposal_payload.get("rationale") or ""),
        )
        return dag_obj.apply_mutation(mutation.to_dict())

    def handle_trigger(self, dag: InvestigationDAG | Dict[str, Any], trigger: AdaptiveDAGTrigger | Dict[str, Any]) -> Dict[str, Any]:
        proposal = self.evaluate(dag, trigger)
        if proposal is None:
            dag_obj = dag if isinstance(dag, InvestigationDAG) else InvestigationDAG.from_dict(dag)
            return {"applied": False, "proposal": None, "dag": dag_obj.to_dict()}
        dag_obj = self.apply(dag, proposal) if self.policy.auto_apply else (dag if isinstance(dag, InvestigationDAG) else InvestigationDAG.from_dict(dag))
        return {"applied": self.policy.auto_apply, "proposal": proposal.to_dict(), "dag": dag_obj.to_dict()}

    def _node_for_trigger(self, dag: InvestigationDAG, trigger: AdaptiveDAGTrigger) -> Dict[str, Any]:
        evidence = dict(trigger.evidence or {})
        capability_id = str(evidence.get("capability_id") or self._capability_for_trigger(trigger.trigger_type))
        allowed_tools = list(evidence.get("allowed_tools") or evidence.get("tools") or [])
        params = dict(evidence.get("params") or {})
        if evidence.get("query") and "query" not in params:
            params["query"] = evidence.get("query")
        mutation_hint = _stable_id("adaptive-node", dag.dag_id, trigger.trigger_type, trigger.reason, evidence)
        return {
            "node_id": mutation_hint,
            "node_type": "capability",
            "label": evidence.get("label") or f"Adaptive pivot: {trigger.trigger_type}",
            "status": "ready",
            "capability_id": capability_id,
            "action_id": evidence.get("action_id") or mutation_hint,
            "objective_ref": dag.objective_ref,
            "task_ref": dag.task_ref,
            "allowed_tools": allowed_tools,
            "params": params,
            "blocking_coverage": bool(evidence.get("blocking_coverage", True)),
            "observations": [],
            "adaptive_metadata": {
                "trigger_type": trigger.trigger_type,
                "trigger_source": trigger.source,
                "trigger_reason": trigger.reason,
                "audit_evidence": evidence,
                "proposal_source": evidence.get("proposal_source") or trigger.source,
                "model_led_plan_id": evidence.get("model_led_plan_id"),
                "model_led_step_id": evidence.get("model_led_step_id"),
                "model_led_dedupe_key": evidence.get("model_led_dedupe_key"),
            },
        }

    @staticmethod
    def _capability_for_trigger(trigger_type: str) -> str:
        if trigger_type in {"coverage_gap", "query_empty", "query_partial"}:
            return "log.search"
        if trigger_type == "hypothesis_new":
            return "ioc.enrich"
        if trigger_type == "analyst_follow_up":
            return "config.capability.explain"
        if trigger_type == "model_led_planner":
            return "log.search"
        return "config.capability.explain"
