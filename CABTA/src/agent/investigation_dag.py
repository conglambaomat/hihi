"""Investigation DAG contracts and strict capability execution helpers."""

from __future__ import annotations

import inspect
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal


NON_TOOL_CAPABILITIES = {"config.capability.explain"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


@dataclass
class InvestigationDAGNode:
    node_id: str
    node_type: str
    label: str
    status: str = "pending"
    capability_id: str = ""
    action_id: str = ""
    objective_ref: str = ""
    task_ref: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    blocking_coverage: bool = False
    observations: List[Dict[str, Any]] = field(default_factory=list)
    adaptive_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationDAG:
    schema_version: str = "investigation-dag/v2"
    dag_id: str = ""
    task_ref: str = ""
    objective_ref: str = ""
    plan_ref: str = ""
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    mutation_ledger: List[Dict[str, Any]] = field(default_factory=list)
    adaptive_policy: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        if not self.dag_id:
            self.dag_id = _stable_id("dag", self.task_ref, self.objective_ref, self.plan_ref, self.nodes)
        self._refresh_summary()

    def _refresh_summary(self) -> None:
        completed = {node.get("node_id") for node in self.nodes if node.get("status") == "completed"}
        ready_node_ids = []
        for node in self.nodes:
            if node.get("status") == "ready":
                ready_node_ids.append(node.get("node_id"))
            elif node.get("node_type") == "capability" and node.get("status") == "pending":
                dependencies = [edge.get("from") for edge in self.edges if edge.get("to") == node.get("node_id")]
                if dependencies and all(dep in completed for dep in dependencies):
                    ready_node_ids.append(node.get("node_id"))
        self.summary = {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "ready_node_ids": ready_node_ids,
            "completed_node_ids": [node.get("node_id") for node in self.nodes if node.get("status") == "completed"],
            "pending_node_ids": [node.get("node_id") for node in self.nodes if node.get("status") == "pending"],
            "schema_version": self.schema_version,
            "mutation_count": len(self.mutation_ledger),
            "latest_mutation_id": (self.mutation_ledger[-1].get("mutation_id") if self.mutation_ledger else None),
            "adaptive": self.schema_version.endswith("/v2"),
        }

    def to_dict(self) -> Dict[str, Any]:
        self._refresh_summary()
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Optional[Dict[str, Any]]) -> "InvestigationDAG":
        data = dict(payload or {})
        valid = set(cls.__dataclass_fields__.keys())
        if data.get("schema_version") == "investigation-dag/v1":
            data.setdefault("mutation_ledger", [])
            data.setdefault("adaptive_policy", {"upgraded_from": "investigation-dag/v1"})
        return cls(**{key: value for key, value in data.items() if key in valid})

    def update_with_observations(self, observations: List[Dict[str, Any]]) -> "InvestigationDAG":
        observations = [dict(item) for item in observations or [] if isinstance(item, dict)]
        for observation in observations:
            capability_id = str(observation.get("capability_id") or "").strip()
            if not capability_id:
                continue
            for node in self.nodes:
                if node.get("node_type") == "capability" and node.get("capability_id") == capability_id:
                    node.setdefault("observations", []).append(observation)
                    node["status"] = "completed"
        self.updated_at = _now_iso()
        self._refresh_summary()
        return self

    def append_mutation(self, mutation: Dict[str, Any]) -> "InvestigationDAG":
        payload = dict(mutation or {})
        payload.setdefault("mutation_id", _stable_id("mut", self.dag_id, len(self.mutation_ledger), payload))
        payload.setdefault("created_at", _now_iso())
        payload.setdefault("status", "applied")
        self.mutation_ledger.append(payload)
        self.updated_at = _now_iso()
        self._refresh_summary()
        return self

    def apply_mutation(self, mutation: Dict[str, Any]) -> "InvestigationDAG":
        payload = dict(mutation or {})
        operation = str(payload.get("operation") or "append_node").strip()
        node = dict(payload.get("node") or {})
        if operation in {"append_node", "insert_node"} and node:
            node.setdefault("node_id", _stable_id("node", self.dag_id, payload.get("trigger"), len(self.nodes)))
            node.setdefault("node_type", "capability")
            node.setdefault("status", "ready" if operation == "append_node" else "pending")
            node.setdefault("observations", [])
            node.setdefault("adaptive_metadata", {"source_mutation": payload.get("mutation_id")})
            if not any(existing.get("node_id") == node.get("node_id") for existing in self.nodes):
                self.nodes.append(node)
            for edge in payload.get("edges") or []:
                if isinstance(edge, dict) and edge not in self.edges:
                    self.edges.append(dict(edge))
        elif operation == "supersede_node":
            target = str(payload.get("target_node_id") or "")
            for existing in self.nodes:
                if existing.get("node_id") == target:
                    existing["status"] = "superseded"
                    existing.setdefault("adaptive_metadata", {})["superseded_by"] = payload.get("mutation_id")
        return self.append_mutation(payload)

    def _unlock_ready_nodes(self) -> None:
        completed = {node.get("node_id") for node in self.nodes if node.get("status") == "completed"}
        for node in self.nodes:
            if node.get("node_type") != "capability" or node.get("status") != "pending":
                continue
            dependencies = [edge.get("from") for edge in self.edges if edge.get("to") == node.get("node_id")]
            if all(dep in completed for dep in dependencies):
                node["status"] = "ready"


class InvestigationDAGBuilder:
    """Build a minimal ordered DAG from objective and capability-plan contracts."""

    def build(self, task_state: Any, objective_contract: Dict[str, Any] | None = None, capability_plan: Dict[str, Any] | None = None) -> InvestigationDAG:
        objective = objective_contract if isinstance(objective_contract, dict) else getattr(task_state, "objective_contract", {}) or {}
        plan = capability_plan if isinstance(capability_plan, dict) else getattr(task_state, "capability_plan", {}) or {}
        task_ref = str(getattr(task_state, "task_id", "") or "")
        objective_ref = str(objective.get("contract_id") or plan.get("objective_ref") or "")
        plan_ref = str(plan.get("plan_id") or "")
        actions = list(plan.get("actions") or [])

        objective_node_id = _stable_id("node-objective", task_ref, objective_ref, objective.get("analyst_objective"))
        nodes: List[Dict[str, Any]] = [
            InvestigationDAGNode(
                node_id=objective_node_id,
                node_type="objective",
                label=str(objective.get("analyst_objective") or getattr(task_state, "analyst_objective", "") or getattr(task_state, "raw_request", "") or "SOC objective"),
                status="completed",
                objective_ref=objective_ref,
                task_ref=task_ref,
            ).to_dict()
        ]
        edges: List[Dict[str, Any]] = []
        previous_id = objective_node_id
        for index, action in enumerate(actions):
            action = dict(action or {})
            capability_id = str(action.get("capability_id") or action.get("capability") or "").strip()
            action_id = str(action.get("action_id") or _stable_id("action", task_ref, capability_id, index))
            node_id = _stable_id("node-capability", task_ref, action_id, capability_id)
            node = InvestigationDAGNode(
                node_id=node_id,
                node_type="capability",
                label=capability_id or action_id,
                status="ready" if index == 0 else "pending",
                capability_id=capability_id,
                action_id=action_id,
                objective_ref=objective_ref,
                task_ref=task_ref,
                allowed_tools=list(action.get("allowed_tools") or []),
                params=dict(action.get("params") or action.get("bound_params") or {}),
                blocking_coverage=bool(action.get("blocking_coverage")),
            ).to_dict()
            nodes.append(node)
            edges.append({"from": previous_id, "to": node_id, "edge_type": "depends_on", "order": index + 1})
            previous_id = node_id

        return InvestigationDAG(task_ref=task_ref, objective_ref=objective_ref, plan_ref=plan_ref, nodes=nodes, edges=edges)


@dataclass
class StrictDAGExecutionResult:
    allowed: bool
    status: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    blocking_reasons: List[str] = field(default_factory=list)
    executed_node_ids: List[str] = field(default_factory=list)
    dag: Dict[str, Any] = field(default_factory=dict)
    node_results: List[Dict[str, Any]] = field(default_factory=list)
    schema_version: str = "strict-dag-execution/v1"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload.setdefault("dag", {})
        payload.setdefault("node_results", [])
        return payload


class StrictDAGExecutor:
    """Execute ready capability nodes through the capability execution envelope only."""

    def __init__(self, *, capability_executor: Any = None, tool_registry: Any = None, max_retries: int = 0, **_: Any) -> None:
        self.capability_executor = capability_executor
        self.tool_registry = tool_registry
        self.max_retries = int(max_retries or 0)

    async def execute(
        self,
        dag: InvestigationDAG | Dict[str, Any],
        *,
        task_state: Any,
        objective_contract: Dict[str, Any] | None = None,
        context: Dict[str, Any] | None = None,
    ) -> StrictDAGExecutionResult:
        dag_obj = dag if isinstance(dag, InvestigationDAG) else InvestigationDAG.from_dict(dag)
        context = dict(context or {})
        evidence: List[Dict[str, Any]] = []
        blocking: List[str] = []
        executed: List[str] = []
        node_results: List[Dict[str, Any]] = []

        while True:
            dag_obj._unlock_ready_nodes()
            ready_nodes = [node for node in dag_obj.nodes if node.get("node_type") == "capability" and node.get("status") == "ready"]
            if not ready_nodes:
                break
            progressed = False
            for node in ready_nodes:
                capability_id = str(node.get("capability_id") or "")
                if capability_id in NON_TOOL_CAPABILITIES:
                    payload = {
                        "capability_id": capability_id,
                        "summary": "Capability help is available without a tool call.",
                        "provenance": {"source": "strict_dag_non_tool_capability"},
                    }
                    evidence.append(payload)
                    executed.append(str(node.get("node_id") or ""))
                    node["status"] = "completed"
                    node.setdefault("observations", []).append(payload)
                    node_results.append({"node_id": node.get("node_id"), "status": "completed", "evidence": payload})
                    progressed = True
                    continue

                envelope = self._prepare_envelope(node, task_state, objective_contract or {}, context)
                if not envelope.get("allowed"):
                    reason = envelope.get("reason") or f"Capability '{capability_id}' is unavailable or blocked."
                    if "unavailable" not in str(reason).lower() and "blocked" not in str(reason).lower():
                        reason = f"Capability '{capability_id}' is unavailable or blocked: {reason}"
                    blocking.append(str(reason))
                    node_results.append({"node_id": node.get("node_id"), "status": "blocked", "reason": str(reason)})
                    dag_obj.updated_at = _now_iso()
                    return StrictDAGExecutionResult(False, "blocked", evidence, blocking, executed, dag_obj.to_dict(), node_results)

                tool_name = str(envelope.get("tool_name") or "")
                if not self._has_executor(tool_name):
                    reason = f"Capability '{capability_id}' is unavailable: tool executor '{tool_name}' is not registered."
                    blocking.append(reason)
                    node_results.append({"node_id": node.get("node_id"), "status": "blocked", "reason": reason})
                    dag_obj.updated_at = _now_iso()
                    return StrictDAGExecutionResult(False, "blocked", evidence, blocking, executed, dag_obj.to_dict(), node_results)

                result = await self._execute_tool(
                    tool_name,
                    dict(envelope.get("params") or {}),
                    capability_id=capability_id,
                    node=node,
                    envelope=envelope,
                    context=context,
                )
                result_payload = dict(result or {}) if isinstance(result, dict) else {"result": result}
                result_payload.setdefault("capability_id", capability_id)
                result_payload.setdefault("tool_name", tool_name)
                result_payload.setdefault("provenance", {"source": "strict_dag_executor", "tool_name": tool_name})
                evidence.append(result_payload)
                executed.append(str(node.get("node_id") or ""))
                node["status"] = "completed"
                node.setdefault("observations", []).append(result_payload)
                node_results.append({"node_id": node.get("node_id"), "status": "completed", "evidence": result_payload})
                progressed = True
            if not progressed:
                break

        dag_obj.updated_at = _now_iso()
        return StrictDAGExecutionResult(True, "completed", evidence, [], executed, dag_obj.to_dict(), node_results)

    def _prepare_envelope(self, node: Dict[str, Any], task_state: Any, objective_contract: Dict[str, Any], context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if self.capability_executor is None:
            return {"allowed": False, "reason": "Capability executor is unavailable."}
        requested_tool = ""
        allowed_tools = list(node.get("allowed_tools") or [])
        if allowed_tools:
            requested_tool = str(allowed_tools[0] or "")
        envelope = self.capability_executor.prepare(
            capability_id=str(node.get("capability_id") or ""),
            task_state=task_state,
            objective_contract=objective_contract,
            requested_tool=requested_tool,
            initial_params=dict(node.get("params") or {}),
            rationale=f"Strict DAG node {node.get('node_id')} execution.",
            context=dict(context or {}),
        )
        return envelope.to_dict() if hasattr(envelope, "to_dict") else dict(envelope or {})

    def _has_executor(self, tool_name: str) -> bool:
        if self.tool_registry is None:
            return False
        get_tool = getattr(self.tool_registry, "get_tool", None)
        if callable(get_tool) and get_tool(tool_name) is not None:
            return True
        return bool(getattr(self.tool_registry, "_executors", {}).get(tool_name))

    async def _execute_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        *,
        capability_id: str = "",
        node: Dict[str, Any] | None = None,
        envelope: Dict[str, Any] | None = None,
        context: Dict[str, Any] | None = None,
    ) -> Any:
        execution_context = dict(context or {})
        execution_context.update(
            {
                "capability_enforced": True,
                "capability_id": capability_id,
                "strict_dag_node_id": (node or {}).get("node_id"),
                "dag_node_id": (node or {}).get("node_id"),
                "dag_mutation_id": ((node or {}).get("adaptive_metadata") or {}).get("source_mutation"),
                "adaptive_dag": bool((node or {}).get("adaptive_metadata")),
                "capability_envelope": dict(envelope or {}),
            }
        )
        if self.tool_registry is not None and hasattr(self.tool_registry, "execute_local_tool"):
            return await self.tool_registry.execute_local_tool(tool_name, _execution_context=execution_context, **params)

        executor = getattr(self.tool_registry, "_executors", {}).get(tool_name) if self.tool_registry is not None else None
        if executor is None:
            raise RuntimeError(f"Tool executor '{tool_name}' is not registered.")
        params = dict(params)
        params["_execution_context"] = execution_context
        try:
            signature = inspect.signature(executor)
            accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())
            if not accepts_kwargs:
                params = {key: value for key, value in params.items() if key in signature.parameters}
        except (TypeError, ValueError):
            pass
        result = executor(**params)
        if inspect.isawaitable(result):
            return await result
        return result
