import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentPhase, AgentState
from src.agent.capability_executor import CapabilityActionExecutor
from src.agent.capability_ontology import CapabilityContract, CapabilityOntology, ToolContract
from src.agent.capability_plugin_registry import CapabilityPluginRegistry
from src.agent.capability_resolver import CapabilityResolver
from src.agent.claim_verifier import ClaimVerifier
from src.agent.final_answer_gate import FinalAnswerGate
from src.agent.investigation_dag import InvestigationDAGBuilder, StrictDAGExecutor
from src.agent.soc_task_state import SOCTaskState
from src.agent.tool_registry import ToolRegistry


class State:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def graph_with(summary, relation="supports"):
    return {
        "nodes": [{"id": "obs:1", "type": "observation", "summary": summary, "tool_name": "local", "quality": 0.9, "source_paths": ["result.summary"]}],
        "edges": [{"source": "obs:1", "target": "claim:1", "relation": relation, "confidence": 0.9}],
    }


def test_graph_claim_verifier_verified_unsupported_contradicted_and_legacy_mode():
    verifier = ClaimVerifier(strict=True)
    verified = verifier.verify(draft_answer="The host is suspicious due to failed login activity.", state=State(evidence_graph=graph_with("host suspicious failed login activity")), objective={})
    assert verified[0].status == "verified"
    assert verified[0].provenance_spans[0]["node_id"] == "obs:1"

    unsupported = verifier.verify(draft_answer="The host is malicious.", state=State(evidence_graph={}), objective={})
    assert unsupported[0].status == "unsupported"

    contradicted = verifier.verify(draft_answer="The host is malicious.", state=State(evidence_graph=graph_with("host is not malicious", relation="contradicts")), objective={})
    assert contradicted[0].status == "contradicted"

    legacy = ClaimVerifier(legacy_mode=True).verify(
        draft_answer="The host has activity.",
        state=State(findings=[{"type": "tool_result", "tool": "x", "step": 1, "result": "host activity"}]),
        objective={},
        strict=False,
    )
    assert legacy[0].status == "verified"


def test_final_answer_gate_blocks_unsupported_strict_claims():
    state = State(execution_mode="production", evidence_graph={}, findings=[{"type": "tool_result", "tool": "x", "step": 1, "result": "unrelated"}], reasoning_state={})
    decision = FinalAnswerGate().evaluate(objective={"contract_id": "obj", "execution_mode": "production"}, state=state, draft_answer="This file is malicious.")
    assert decision.allowed is False
    assert decision.downgraded_claims[0].status == "unsupported"


class Plugin:
    def __init__(self, plugin_id="p.good", version="1.0.0", capabilities=None, dependencies=None, fail_start=False):
        self.plugin_id = plugin_id
        self.version = version
        self.capabilities = capabilities or [CapabilityContract("custom.cap", "Custom", ["test"], [], ["facet"], [ToolContract("custom_tool", "custom.cap", {"type": "object"}, ["facet"], "primary")])]
        self.dependencies = dependencies or {}
        self.events = []
        self.fail_start = fail_start

    def initialize(self, ontology):
        self.events.append("initialize")

    def start(self, ontology):
        self.events.append("start")
        if self.fail_start:
            raise RuntimeError("boom")

    def stop(self, ontology):
        self.events.append("stop")

    def unload(self, ontology):
        self.events.append("unload")


def test_plugin_registry_lifecycle_validation_dependencies_isolation_and_ordering():
    registry = CapabilityPluginRegistry(CapabilityOntology(capabilities=[]), isolate_errors=True)
    bad = Plugin(plugin_id="bad", version="1", capabilities=[])
    assert registry.register(bad).state == "rejected"

    dep_miss = Plugin(plugin_id="dep", version="1.0.0", dependencies={"missing": ">=1.0.0"})
    assert registry.register(dep_miss).state == "rejected"

    failing = Plugin(plugin_id="a.fail", version="1.0.0", fail_start=True)
    good = Plugin(plugin_id="b.good", version="1.0.0", capabilities=[CapabilityContract("b.cap", "B", ["test"], [], ["facet"], [])])
    registry.discover([good, failing])
    registry.initialize_all()
    registry.start_all()
    status = registry.status()
    states = {p["plugin_id"]: p["state"] for p in status["plugins"]}
    assert states["a.fail"] == "failed"
    assert states["b.good"] == "running"
    assert [p["plugin_id"] for p in status["plugins"]] == sorted(p["plugin_id"] for p in status["plugins"])
    assert registry.ontology.get("b.cap") is not None


@pytest.mark.asyncio
async def test_strict_dag_executor_runs_captures_provenance_and_blocks_policy():
    registry = ToolRegistry()

    async def analyze_log_artifact(raw_log_event: str):
        return {"summary": "failed login observed", "provenance": {"source": "unit-test", "span": "raw_log_event"}}

    registry.register_local_tool("analyze_log_artifact", "x", {"type": "object"}, "analysis", analyze_log_artifact, capability_id="log.analyze.inline")
    resolver = CapabilityResolver(get_tool=registry.get_tool)
    cap_exec = CapabilityActionExecutor(capability_resolver=resolver, tool_registry=registry)
    task = SOCTaskState(session_id="s", raw_request="Investigate log")
    task.compiled_input = {"raw_log_event": "failed login", "lane": "log_identity"}
    task.objective_contract = {"contract_id": "obj", "analyst_objective": "Investigate log"}
    plan = {"actions": [{"action_id": "a1", "capability_id": "log.analyze.inline", "params": {"raw_log_event": "failed login"}}]}
    dag = InvestigationDAGBuilder().build(task, task.objective_contract, plan)

    result = await StrictDAGExecutor(capability_executor=cap_exec, tool_registry=registry).execute(dag, task_state=task, objective_contract=task.objective_contract)
    assert result.allowed is True
    assert result.evidence[0]["provenance"]["source"] == "unit-test"

    bad_plan = {"actions": [{"action_id": "a2", "capability_id": "log.search"}]}
    bad_dag = InvestigationDAGBuilder().build(task, task.objective_contract, bad_plan)
    blocked = await StrictDAGExecutor(capability_executor=cap_exec, tool_registry=registry).execute(bad_dag, task_state=task, objective_contract=task.objective_contract)
    assert blocked.allowed is False
    assert "blocked" in blocked.status


@pytest.mark.asyncio
async def test_strict_dag_handles_capability_help_as_non_tool_direct_node():
    registry = ToolRegistry()
    cap_exec = CapabilityActionExecutor(capability_resolver=CapabilityResolver(get_tool=registry.get_tool), tool_registry=registry)
    task = SOCTaskState(session_id="s", raw_request="ban co the giup toi duoc gi")
    task.required_capabilities = ["config.capability.explain"]
    task.objective_contract = {"contract_id": "obj", "analyst_objective": "ban co the giup toi duoc gi"}
    plan = {"actions": [{"action_id": "a-help", "capability_id": "config.capability.explain"}]}
    dag = InvestigationDAGBuilder().build(task, task.objective_contract, plan)

    result = await StrictDAGExecutor(capability_executor=cap_exec, tool_registry=registry).execute(dag, task_state=task, objective_contract=task.objective_contract)

    assert result.allowed is True
    assert result.evidence[0]["capability_id"] == "config.capability.explain"
    assert result.evidence[0]["provenance"]["source"] == "strict_dag_non_tool_capability"


@pytest.mark.asyncio
async def test_strict_dag_raw_log_resolves_allowed_tool_and_collects_evidence():
    registry = ToolRegistry()

    async def analyze_log_artifact(raw_log_text: str, **kwargs):
        return {"summary": "sysmon event analyzed", "provenance": {"tool": "analyze_log_artifact", "span": "raw_log_text"}}

    registry.register_local_tool("analyze_log_artifact", "x", {"type": "object"}, "analysis", analyze_log_artifact, capability_id="log.analyze.inline")
    cap_exec = CapabilityActionExecutor(capability_resolver=CapabilityResolver(get_tool=registry.get_tool), tool_registry=registry)
    task = SOCTaskState(session_id="s", raw_request="EventID=1 Image=powershell.exe")
    task.compiled_input = {"input_kind": "raw_log_artifact", "compiled_input_id": "ci-log", "parser": {"parsed_fields": {"EventID": "1"}}}
    task.required_capabilities = ["log.analyze.inline"]
    task.objective_contract = {"contract_id": "obj", "analyst_objective": "Analyze Sysmon log", "compiled_input": task.compiled_input}
    plan = {"actions": [{"action_id": "a-log", "capability_id": "log.analyze.inline", "allowed_tools": ["analyze_log_artifact"]}]}
    dag = InvestigationDAGBuilder().build(task, task.objective_contract, plan)

    result = await StrictDAGExecutor(capability_executor=cap_exec, tool_registry=registry).execute(dag, task_state=task, objective_contract=task.objective_contract)

    assert result.allowed is True
    assert result.evidence[0]["tool_name"] == "analyze_log_artifact"
    assert result.evidence[0]["summary"] == "sysmon event analyzed"


@pytest.mark.asyncio
async def test_strict_dag_missing_executable_tool_has_clear_unavailable_message():
    registry = ToolRegistry()
    cap_exec = CapabilityActionExecutor(capability_resolver=CapabilityResolver(get_tool=registry.get_tool), tool_registry=registry)
    task = SOCTaskState(session_id="s", raw_request="search logs for host x")
    task.objective_contract = {"contract_id": "obj", "analyst_objective": "search logs for host x"}
    dag = InvestigationDAGBuilder().build(task, task.objective_contract, {"actions": [{"action_id": "a-search", "capability_id": "log.search"}]})

    result = await StrictDAGExecutor(capability_executor=cap_exec, tool_registry=registry).execute(dag, task_state=task, objective_contract=task.objective_contract)

    assert result.allowed is False
    assert "Capability 'log.search' is unavailable" in result.blocking_reasons[0]
    assert "Resolved tool name is required" not in result.blocking_reasons[0]


@pytest.mark.asyncio
async def test_strict_dag_loop_enters_acting_from_idle_via_thinking_for_raw_sysmon_log():
    store = MagicMock()
    store.get_session.return_value = {"metadata": {}}
    loop = AgentLoop(
        config={"agent": {"execution": {"strict_dag_mode": True}}},
        tool_registry=ToolRegistry(),
        agent_store=store,
    )
    sysmon_log = (
        "index=wineventlog sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational "
        "host=HR-WIN-001 user=trang.nguyen parent_process=stage2.exe "
        "CommandLine=\"powershell.exe -NoProfile Get-WmiObject -Class Win32_Bios\" "
        "src_ip=10.10.20.15 sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
    state = AgentState(session_id="sess-sysmon", goal=sysmon_log)
    state.reasoning_state = {
        "objective_contract": {"contract_id": "obj-sysmon", "analyst_objective": "Investigate pasted Sysmon log"},
        "compiled_input": {"raw_log_event": sysmon_log, "lane": "log_endpoint"},
        "investigation_dag": {"schema_version": "investigation-dag/v1", "nodes": [], "edges": []},
    }
    loop.strict_dag_executor.execute = AsyncMock(return_value=SimpleNamespace(
        allowed=True,
        to_dict=lambda: {"allowed": True, "status": "completed", "dag": {}, "node_results": [], "evidence": []},
    ))
    loop._generate_summary = AsyncMock(return_value="Strict DAG completed.")
    loop._evaluate_final_answer_gate = MagicMock(return_value=SimpleNamespace(
        allowed=True,
        to_dict=lambda: {"structured_verdict": {"verdict": "inconclusive"}, "evidence_chips": [], "claim_evidence_map": {}},
    ))

    await loop._run_strict_dag_loop("sess-sysmon", state)

    loop.strict_dag_executor.execute.assert_awaited_once()
    assert state.phase == AgentPhase.COMPLETED
    assert "Invalid transition: idle -> acting" not in state.errors


@pytest.mark.asyncio
async def test_strict_dag_loop_safe_stops_timeout_instead_of_remaining_active():
    store = MagicMock()
    store.get_session.return_value = {"metadata": {}}
    loop = AgentLoop(
        config={"agent": {"execution": {"strict_dag_mode": True, "strict_dag_timeout_seconds": 0.01}}},
        tool_registry=ToolRegistry(),
        agent_store=store,
    )
    state = AgentState(session_id="sess-timeout", goal="Investigate WMI activity in Splunk logs")
    state.reasoning_state = {
        "objective_contract": {"contract_id": "obj-timeout", "analyst_objective": "Investigate WMI activity"},
        "compiled_input": {"lane": "log_endpoint"},
        "investigation_dag": {"schema_version": "investigation-dag/v1", "nodes": [], "edges": []},
    }

    async def never_finishes(*_args, **_kwargs):
        await asyncio.sleep(60)

    loop.strict_dag_executor.execute = AsyncMock(side_effect=never_finishes)

    await loop._run_strict_dag_loop("sess-timeout", state)

    assert state.phase == AgentPhase.COMPLETED
    assert state.step_count == 1
    assert any(finding.get("type") == "capability_degraded" for finding in state.findings)
    assert any(finding.get("type") == "final_answer" for finding in state.findings)
    assert store.add_step.call_args.args[:3] == ("sess-timeout", 0, "runtime_safe_stop")
    assert store.update_session_status.call_args.args[:2] == ("sess-timeout", "completed")
