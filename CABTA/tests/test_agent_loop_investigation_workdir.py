import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentPhase, AgentState
from src.agent.agent_store import AgentStore
from src.agent.investigation_workdir import InvestigationWorkdirService
from src.agent.tool_registry import ToolRegistry


class _MemoryCaseStore:
    def __init__(self, cases=None):
        self.cases = dict(cases or {})

    def get_case(self, case_id):
        return self.cases.get(case_id)



def _loop(tmp_path, service=None, case_store=None):
    registry = ToolRegistry()
    store = AgentStore(db_path=str(tmp_path / "agent.db"))
    loop = AgentLoop(
        config={"llm": {"provider": "router"}, "agent": {"max_steps": 1}},
        tool_registry=registry,
        agent_store=store,
        case_store=case_store,
        investigation_workdir_service=service,
    )
    return loop, store


def test_agent_loop_optional_workdir_absent_does_not_break_metadata_persistence(tmp_path):
    loop, store = _loop(tmp_path, service=None)
    session_id = store.create_session("Investigate 8.8.8.8", metadata={})
    state = AgentState(session_id=session_id, goal="Investigate 8.8.8.8", max_steps=1)

    loop._refresh_reasoning_outputs(session_id, state)

    metadata = store.get_session(session_id)["metadata"]
    assert "investigation_workdir" not in metadata
    assert metadata["deterministic_decision_output"]["verdict"] == "UNKNOWN"


def test_agent_loop_initializes_and_records_workdir_summary(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path / "workdirs")
    loop, store = _loop(tmp_path, service=service)

    summary = loop._initialize_investigation_workdir(
        session_id="sess-1",
        goal="Investigate 8.8.8.8",
        case_id="case-1",
        thread_id="thread-1",
        metadata={"investigation_id": "custom-investigation", "api_key": "secret"},
        investigation_plan={"steps": [{"title": "Collect evidence"}]},
    )

    assert summary["investigation_id"] == "custom-investigation"
    root = service.get_path("custom-investigation")
    assert root.exists()
    assert "Investigate 8.8.8.8" in (root / "plan.md").read_text(encoding="utf-8")
    assert "api_key" not in (root / "context.md").read_text(encoding="utf-8")
    assert summary["verdict_boundary"] == "deterministic_scoring_remains_authoritative"


def test_agent_loop_mirrors_observation_reasoning_and_review(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path / "workdirs")
    loop, store = _loop(tmp_path, service=service)
    session_id = store.create_session(
        "Investigate 8.8.8.8",
        metadata={"investigation_workdir": {"investigation_id": "sess-workdir"}},
    )
    service.create_or_get("sess-workdir", session_id=session_id)
    state = AgentState(session_id=session_id, goal="Investigate 8.8.8.8", max_steps=3)
    state.phase = AgentPhase.OBSERVING
    state.step_count = 1
    state.reasoning_state = {"open_questions": ["Need DNS context"]}
    state.entity_state = {"entities": {"ip:8.8.8.8": {"value": "8.8.8.8"}}}
    state.evidence_state = {"nodes": []}
    state.deterministic_decision = {"verdict": "CLEAN", "source": "investigate_ioc"}
    state.agentic_explanation = {"summary": "Looks clean"}
    state.unresolved_questions = ["Need DNS context"]

    loop._mirror_observation_to_workdir(
        session_id=session_id,
        state=state,
        tool_name="investigate_ioc",
        params={"ioc": "8.8.8.8", "token": "secret"},
        result={"verdict": "CLEAN"},
    )
    loop._mirror_reasoning_to_workdir(session_id, state)
    loop._write_terminal_review_to_workdir(
        session_id,
        state,
        {"summary": "Done", "status": "completed"},
    )

    root = service.get_path("sess-workdir")
    observation = service.read_json("sess-workdir", "evidence/observations/step-0001-investigate_ioc.json")
    decision = service.read_json("sess-workdir", "deterministic_decision.json")
    explanation = service.read_json("sess-workdir", "agentic_explanation.json")
    metadata = store.get_session(session_id)["metadata"]

    assert observation["params"]["token"] == "[REDACTED]"
    assert decision["verdict_boundary"] == "deterministic_aisa_scoring"
    assert explanation["verdict_boundary"] == "non_authoritative"
    assert "Done" in (root / "review.md").read_text(encoding="utf-8")
    assert metadata["investigation_workdir"]["artifact_count"] >= 1


def test_agent_loop_mirrors_retry_coverage_and_hypothesis_requirement_artifacts(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path / "workdirs")
    loop, store = _loop(tmp_path, service=service)
    session_id = store.create_session(
        "Investigate alice logon",
        metadata={"investigation_workdir": {"investigation_id": "retry-workdir"}},
    )
    service.create_or_get("retry-workdir", session_id=session_id)
    state = AgentState(session_id=session_id, goal="Investigate alice logon", max_steps=3)
    state.investigation_plan = {"lane": "log_identity"}
    state.step_count = 1
    state.findings = [{"type": "tool_result", "tool": "search_logs", "result": {"status": "executed"}, "step": 1}]
    state.reasoning_state = loop.hypothesis_manager.bootstrap(
        state.goal,
        session_id,
        investigation_plan=state.investigation_plan,
    )
    state.reasoning_state["hypotheses"] = [
        {
            "id": "hyp-identity",
            "statement": "Identity compromise may be present",
            "hypothesis_type": "identity_compromise",
            "required_evidence": [
                {
                    "contract_id": "identity-contract",
                    "required_observation_types": ["auth_event"],
                    "required_entities": ["user", "host"],
                    "required_relations": ["authenticated_from"],
                }
            ],
        }
    ]

    loop._refresh_reasoning_outputs(
        session_id,
        state,
        tool_name="search_logs",
        params={"query": {"splunk": ["search index=auth user=alice | head 50"]}},
        result={
            "status": "executed",
            "results_count": 0,
            "queries": {"splunk": ["search index=auth user=alice | head 50"]},
            "coverage_matrix": {
                "coverage_status": "partial",
                "overall_score": 0.25,
                "covered_facets": ["user"],
                "missing_facets": ["host", "session", "process"],
                "blocking_gaps": [{"facet": "host"}],
                "retry_recommended": True,
            },
            "investigation_query_plan": {"objective": "auth_linkage", "expected_facets": ["user", "host", "session", "process"]},
        },
    )

    retry_events = service.read_json("retry-workdir", "retry_audit_events.json")
    coverage_delta = service.read_json("retry-workdir", "latest_coverage_delta.json")
    requirement_coverage = service.read_json("retry-workdir", "hypothesis_requirement_coverage.json")

    assert retry_events[-1]["event_type"] == "retry_backtracking_decision"
    assert retry_events[-1]["authoritative"] is False
    assert coverage_delta["authoritative"] is False
    assert "user" in coverage_delta["newly_covered_facets"]
    assert requirement_coverage["authoritative"] is False
    assert requirement_coverage["cells"][0]["relation_basis"]["authenticated_from"] == "missing"


def test_agent_loop_resume_from_workdir_creates_lineage_session(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path / "workdirs")
    loop, store = _loop(tmp_path, service=service)
    source_session = store.create_session(
        "Investigate source",
        case_id="case-r",
        metadata={"investigation_workdir": {"investigation_id": "resume-source"}},
    )
    service.create_or_get("resume-source", session_id=source_session, case_id="case-r", thread_id="thread-r")
    service.write_json("resume-source", "hypotheses.json", {"status": "supported", "open_questions": ["Need fresh DNS"]})
    service.write_text("resume-source", "artifacts/reports/source.md", "source evidence", artifact_kind="report")

    result = asyncio.run(loop.resume_from_workdir("resume-source", max_steps=1))

    assert result["session_id"] != source_session
    resumed = store.get_session(result["session_id"])
    metadata = resumed["metadata"]
    assert metadata["resume_mode"] == "workdir_deep_resume"
    assert metadata["source_workdir_investigation_id"] == "resume-source"
    assert metadata["workdir_resume_validated"] is True
    assert metadata["chat_follow_up_requires_fresh_evidence"] is True
    assert metadata["source_session_id"] == source_session
    assert metadata["source_workdir_id"] == "resume-source"
    assert metadata["source_case_id"] == "case-r"
    assert metadata["workdir_resume_source_payload"]["source_session_id"] == source_session
    assert metadata["workdir_resume_source_payload"]["source_case_id"] == "case-r"
    assert metadata["workdir_resume_source_payload"]["source_workdir_session_id"] == source_session


def test_agent_loop_resume_from_session_only_workdir_does_not_promote_session_id_to_case_id(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path / "workdirs")
    loop, store = _loop(tmp_path, service=service, case_store=_MemoryCaseStore())
    source_session = store.create_session(
        "Investigate source session only",
        metadata={"investigation_workdir": {"investigation_id": "0db63b514aa1"}},
    )
    service.create_or_get("0db63b514aa1", session_id=source_session, case_id=None, thread_id="thread-session-only")
    service.write_json("0db63b514aa1", "hypotheses.json", {"status": "needs_evidence", "open_questions": ["Need fresh IOC validation"]})

    result = asyncio.run(loop.resume_from_workdir("0db63b514aa1", max_steps=1))

    resumed = store.get_session(result["session_id"])
    metadata = resumed["metadata"]
    assert resumed["case_id"] is None
    assert metadata["source_session_id"] == source_session
    assert metadata["source_workdir_id"] == "0db63b514aa1"
    assert metadata["source_case_id"] is None
    assert metadata["source_case_id_present"] is False
    assert metadata["workdir_resume_case_context_available"] is False
    assert metadata["workdir_resume_source_payload"]["source_session_id"] == source_session
    assert metadata["workdir_resume_source_payload"]["source_workdir_id"] == "0db63b514aa1"
    assert metadata["workdir_resume_source_payload"]["source_case_id"] is None

    state = loop._active_sessions[result["session_id"]]
    loop.tools.register_default_tools({})
    filtered = loop._filter_tools_for_goal(loop.tools.get_tools_for_llm(), state.goal, state)
    names = {tool.get("function", {}).get("name") for tool in filtered}
    assert "get_case_context" not in names


def test_agent_loop_resume_from_case_linked_workdir_preserves_valid_case_context(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path / "workdirs")
    case_store = _MemoryCaseStore({"case-linked": {"id": "case-linked", "analyses": []}})
    loop, store = _loop(tmp_path, service=service, case_store=case_store)
    source_session = store.create_session(
        "Investigate linked case",
        case_id="case-linked",
        metadata={"investigation_workdir": {"investigation_id": "linked-workdir"}},
    )
    service.create_or_get("linked-workdir", session_id=source_session, case_id="case-linked", thread_id="thread-linked")

    result = asyncio.run(loop.resume_from_workdir("linked-workdir", max_steps=1))

    resumed = store.get_session(result["session_id"])
    metadata = resumed["metadata"]
    assert resumed["case_id"] == "case-linked"
    assert metadata["source_session_id"] == source_session
    assert metadata["source_workdir_id"] == "linked-workdir"
    assert metadata["source_case_id"] == "case-linked"
    assert metadata["source_case_id_present"] is True
    assert metadata["workdir_resume_case_context_available"] is True


def test_agent_loop_workdir_failures_are_fail_safe(tmp_path):
    failing_service = MagicMock()
    failing_service.create_or_get.side_effect = RuntimeError("disk unavailable")
    loop, _store = _loop(tmp_path, service=failing_service)

    summary = loop._initialize_investigation_workdir(
        session_id="sess-1",
        goal="Investigate 8.8.8.8",
        case_id=None,
        thread_id=None,
        metadata={},
        investigation_plan={},
    )

    assert summary is None
