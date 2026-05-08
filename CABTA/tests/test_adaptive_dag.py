from src.agent.adaptive_dag import AdaptiveDAGController, AdaptiveDAGTrigger, ADAPTIVE_DAG_TRIGGERS
from src.agent.investigation_dag import InvestigationDAG, InvestigationDAGBuilder
from src.agent.soc_task_state import SOCTaskState


def test_dag_v2_accepts_v1_and_records_mutation_ledger():
    legacy = {"schema_version": "investigation-dag/v1", "dag_id": "dag-1", "nodes": [], "edges": []}
    dag = InvestigationDAG.from_dict(legacy)
    assert dag.schema_version == "investigation-dag/v1"
    controller = AdaptiveDAGController()
    result = controller.handle_trigger(dag, AdaptiveDAGTrigger("coverage_gap", "need user facet", evidence={"capability_id": "log.search"}))
    updated = result["dag"]
    assert updated["mutation_ledger"]
    assert updated["summary"]["mutation_count"] == 1
    assert updated["nodes"][0]["adaptive_metadata"]["trigger_type"] == "coverage_gap"


def test_adaptive_controller_supports_required_triggers():
    assert {"coverage_gap", "query_empty", "query_partial", "manual_required", "tool_failure", "policy_block", "hypothesis_new", "final_gate_blocked", "analyst_follow_up"} <= ADAPTIVE_DAG_TRIGGERS
    task = SOCTaskState(session_id="s1", raw_request="Investigate auth logs")
    dag = InvestigationDAGBuilder().build(task, {"contract_id": "obj-1"}, {"actions": []})
    controller = AdaptiveDAGController()
    for trigger in sorted(ADAPTIVE_DAG_TRIGGERS):
        proposal = controller.evaluate(dag, {"trigger_type": trigger, "reason": "test"})
        assert proposal is not None
        assert proposal.node["status"] == "ready"
