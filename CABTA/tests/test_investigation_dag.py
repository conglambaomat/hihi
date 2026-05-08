import asyncio

from src.agent.compile_preview_service import CompilePreviewService
from src.agent.investigation_dag import InvestigationDAG, InvestigationDAGBuilder, StrictDAGExecutor
from src.agent.soc_task_state import SOCTaskState


def test_compile_preview_includes_real_investigation_dag():
    contract = CompilePreviewService().compile_and_plan(
        "Investigate raw Windows log: user alice failed login from 10.0.0.5 then success",
        {"session_id": "preview-test"},
    ).to_dict()

    dag = contract["investigation_dag"]
    assert dag["schema_version"] == "investigation-dag/v2"
    assert "mutation_ledger" in dag
    assert dag["task_ref"] == contract["task_state"]["task_id"]
    assert len(dag["nodes"]) >= 2
    assert any(node["node_type"] == "objective" for node in dag["nodes"])
    capability_nodes = [node for node in dag["nodes"] if node["node_type"] == "capability"]
    assert capability_nodes
    assert capability_nodes[0]["status"] == "ready"
    assert dag["edges"]
    assert contract["task_state"]["investigation_dag"]["dag_id"] == dag["dag_id"]


def test_investigation_dag_updates_matching_capability_observations():
    task = SOCTaskState(session_id="s1", raw_request="Investigate suspicious auth logs")
    task.compiled_input = {"compiled_input_id": "compiled-1", "lane": "log_identity"}
    objective = {"contract_id": "obj-1", "analyst_objective": "Investigate suspicious auth logs"}
    plan = {
        "objective_ref": "obj-1",
        "compiled_input_ref": "compiled-1",
        "actions": [
            {"action_id": "act-1", "capability_id": "log.analyze.inline", "blocking_coverage": True},
            {"action_id": "act-2", "capability_id": "ioc.enrich", "blocking_coverage": True},
        ],
    }

    dag = InvestigationDAGBuilder().build(task, objective, plan)
    assert [node["status"] for node in dag.to_dict()["nodes"] if node["node_type"] == "capability"] == ["ready", "pending"]

    updated = InvestigationDAG.from_dict(dag.to_dict()).update_with_observations([
        {"capability_id": "log.analyze.inline", "summary": "Observed failed and successful auth sequence"}
    ])
    payload = updated.to_dict()
    first = next(node for node in payload["nodes"] if node.get("capability_id") == "log.analyze.inline")
    second = next(node for node in payload["nodes"] if node.get("capability_id") == "ioc.enrich")
    assert first["status"] == "completed"
    assert first["observations"][0]["summary"].startswith("Observed failed")
    assert second["status"] == "pending"
    assert payload["summary"]["ready_node_ids"] == [second["node_id"]]


class _Envelope:
    def __init__(self, capability_id, tool_name, params):
        self.capability_id = capability_id
        self.tool_name = tool_name
        self.params = dict(params)

    def to_dict(self):
        return {
            "allowed": True,
            "capability_id": self.capability_id,
            "tool_name": self.tool_name,
            "params": self.params,
        }


class _RecordingCapabilityExecutor:
    def __init__(self):
        self.contexts = []

    def prepare(self, *, capability_id, requested_tool, initial_params, context=None, **_kw):
        self.contexts.append(dict(context or {}))
        return _Envelope(capability_id, requested_tool, initial_params)


class _PublicBoundaryRegistry:
    def __init__(self):
        self.calls = []
        self._executors = {"tool.one": object(), "tool.two": object()}

    def get_tool(self, name):
        return {"name": name} if name in self._executors else None

    async def execute_local_tool(self, name, **kwargs):
        self.calls.append((name, kwargs))
        return {"status": "executed", "tool_name": name, "context_seen": kwargs.get("_execution_context", {})}


def test_strict_dag_executor_accepts_context_uses_public_tool_boundary_and_unlocks_nodes():
    async def _run():
        task = SOCTaskState(session_id="s1", raw_request="Investigate Sysmon WMI alert")
        objective = {"contract_id": "obj-ctx", "analyst_objective": "Investigate Sysmon WMI alert"}
        plan = {
            "objective_ref": "obj-ctx",
            "actions": [
                {"action_id": "act-1", "capability_id": "log.search", "allowed_tools": ["tool.one"], "params": {"query": "EventCode=1"}},
                {"action_id": "act-2", "capability_id": "ioc.extract", "allowed_tools": ["tool.two"], "params": {"text": "powershell Get-WmiObject"}},
            ],
        }
        dag = InvestigationDAGBuilder().build(task, objective, plan)
        capability_executor = _RecordingCapabilityExecutor()
        registry = _PublicBoundaryRegistry()

        result = await StrictDAGExecutor(capability_executor=capability_executor, tool_registry=registry).execute(
            dag,
            task_state=task,
            objective_contract=objective,
            context={"case_id": "case-1", "log_query_plan": {"source": "sysmon"}},
        )

        payload = result.to_dict()
        assert payload["allowed"] is True
        assert "dag" in payload and "node_results" in payload
        assert len(payload["executed_node_ids"]) == 2
        assert [call[0] for call in registry.calls] == ["tool.one", "tool.two"]
        first_context = registry.calls[0][1]["_execution_context"]
        assert first_context["case_id"] == "case-1"
        assert first_context["capability_enforced"] is True
        assert first_context["capability_id"] == "log.search"
        assert capability_executor.contexts[0]["log_query_plan"] == {"source": "sysmon"}
        assert all(node["status"] == "completed" for node in payload["dag"]["nodes"] if node["node_type"] == "capability")
    asyncio.run(_run())
