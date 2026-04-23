import sys
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.case_memory_service import CaseMemoryService


def test_get_case_memory_prefers_published_memory_payload():
    case_store = MagicMock()
    agent_store = MagicMock()
    case_store.get_case.return_value = {
        "workflows": [{"session_id": "sess-1"}],
        "events": [],
    }
    agent_store.get_session.return_value = {
        "id": "sess-1",
        "summary": "Session summary",
        "metadata": {
            "thread_id": "thread-1",
            "memory": {
                "published": {
                    "reasoning_state": {"status": "published"},
                    "accepted_facts": [{"summary": "published fact"}],
                    "root_cause_assessment": {
                        "primary_root_cause": "Published root cause",
                        "summary": "Published root cause summary.",
                    },
                }
            },
            "accepted_facts": [{"summary": "legacy fact"}],
            "reasoning_state": {"status": "legacy"},
        },
    }

    service = CaseMemoryService(case_store=case_store, agent_store=agent_store)

    result = service.get_case_memory("case-1")

    assert result["latest_session_id"] == "sess-1"
    assert result["thread_id"] == "thread-1"
    assert result["memory_scope"] == "published"
    assert result["authoritative_memory_scope"] == "published"
    assert result["authoritative_snapshot"]["reasoning_state"]["status"] == "published"
    assert result["authoritative_snapshot"]["accepted_facts"][0]["summary"] == "published fact"
    assert result["authoritative_snapshot"]["root_cause_assessment"]["primary_root_cause"] == "Published root cause"
    assert result["memory_snapshot"] == result["authoritative_snapshot"]
    assert "accepted_snapshot" not in result
    assert result["memory_lifecycle"] == "published"
    assert result["memory_kind"] == "authoritative_case_truth"
    assert result["memory_is_authoritative"] is True
    assert result["publication_scope"] == "published"
    assert "compatibility_aliases" not in result
    assert result["summary"] == "Published root cause summary."
    assert result["memory_boundary"]["case_id"] == "case-1"
    assert result["memory_boundary"]["publication_scope"] == "published"


def test_get_case_memory_uses_lifecycle_accepted_memory_when_present():
    case_store = MagicMock()
    agent_store = MagicMock()
    case_store.get_case.return_value = {
        "workflows": [{"session_id": "sess-2"}],
        "events": [],
    }
    agent_store.get_session.return_value = {
        "id": "sess-2",
        "summary": "Session summary",
        "metadata": {
            "thread_id": "thread-2",
            "snapshot_lifecycle": "accepted",
            "accepted_memory": {
                "reasoning_state": {"status": "accepted-lifecycle"},
                "accepted_facts": [{"summary": "accepted lifecycle fact"}],
                "root_cause_assessment": {
                    "primary_root_cause": "Lifecycle root cause",
                    "summary": "Lifecycle root cause summary.",
                },
                "entity_summary": {"relationships": [{"id": "rel-accepted"}]},
                "evidence_timeline": [{"summary": "Accepted timeline event"}],
                "evidence_edges": [{"id": "edge-accepted"}],
                "evidence_quality_summary": {"average_quality": 0.88},
            },
            "reasoning_state": {"status": "working"},
            "accepted_facts": [{"summary": "legacy accepted fact"}],
        },
    }

    service = CaseMemoryService(case_store=case_store, agent_store=agent_store)

    result = service.get_case_memory("case-2")

    assert result["memory_scope"] == "accepted"
    assert result["authoritative_memory_scope"] == "accepted"
    assert result["authoritative_snapshot"]["reasoning_state"]["status"] == "accepted-lifecycle"
    assert result["authoritative_snapshot"]["accepted_facts"][0]["summary"] == "accepted lifecycle fact"
    assert result["authoritative_snapshot"]["entity_state"]["relationships"][0]["id"] == "rel-accepted"
    assert result["authoritative_snapshot"]["evidence_state"]["timeline"][0]["summary"] == "Accepted timeline event"
    assert result["authoritative_snapshot"]["evidence_state"]["edges"][0]["id"] == "edge-accepted"
    assert result["authoritative_snapshot"]["evidence_quality_summary"]["average_quality"] == 0.88
    assert result["authoritative_snapshot"]["root_cause_assessment"]["primary_root_cause"] == "Lifecycle root cause"
    assert result["memory_snapshot"] == result["authoritative_snapshot"]
    assert "accepted_snapshot" not in result
    assert result["memory_lifecycle"] == "accepted"
    assert result["memory_kind"] == "authoritative_case_truth"
    assert result["memory_is_authoritative"] is True
    assert result["publication_scope"] == "accepted"
    assert "compatibility_aliases" not in result
    assert result["thread_id"] == "thread-2"
    assert result["memory_boundary"]["thread_id"] == "thread-2"
    assert result["memory_boundary"]["publication_scope"] == "accepted"



def test_get_case_memory_prefers_authoritative_payload_thread_boundary_over_stale_metadata():
    case_store = MagicMock()
    agent_store = MagicMock()
    case_store.get_case.return_value = {
        "workflows": [{"session_id": "sess-boundary"}],
        "events": [],
    }
    agent_store.get_session.return_value = {
        "id": "sess-boundary",
        "summary": "Boundary summary",
        "metadata": {
            "thread_id": "thread-stale",
            "snapshot_lifecycle": "published",
            "accepted_memory": {
                "thread_id": "thread-authoritative",
                "memory_boundary": {
                    "case_id": "case-boundary",
                    "thread_id": "thread-authoritative",
                    "session_id": "sess-boundary",
                    "publication_scope": "published",
                },
                "reasoning_state": {"status": "published"},
                "accepted_facts": [{"summary": "authoritative fact"}],
                "root_cause_assessment": {
                    "primary_root_cause": "Authoritative root cause",
                    "summary": "Authoritative boundary summary.",
                },
            },
        },
    }

    service = CaseMemoryService(case_store=case_store, agent_store=agent_store)

    result = service.get_case_memory("case-boundary")

    assert result["thread_id"] == "thread-authoritative"
    assert result["memory_boundary"]["case_id"] == "case-boundary"
    assert result["memory_boundary"]["thread_id"] == "thread-authoritative"
    assert result["memory_boundary"]["session_id"] == "sess-boundary"
    assert result["memory_boundary"]["publication_scope"] == "published"
    assert result["summary"] == "Authoritative boundary summary."
    assert result["authoritative_snapshot"]["memory_scope"] == "published"
    assert result["authoritative_snapshot"]["authoritative_memory_scope"] == "published"
    assert result["authoritative_snapshot"]["memory_kind"] == "authoritative_case_truth"
    assert result["authoritative_snapshot"]["memory_is_authoritative"] is True
    assert result["authoritative_snapshot"]["publication_scope"] == "published"
    assert result["authoritative_snapshot"]["memory_boundary"] == result["memory_boundary"]


def test_get_case_memory_prefers_published_session_over_accepted_session():
    case_store = MagicMock()
    agent_store = MagicMock()
    case_store.get_case.return_value = {
        "workflows": [{"session_id": "sess-accepted"}, {"session_id": "sess-published"}],
        "events": [],
    }

    sessions = {
        "sess-accepted": {
            "id": "sess-accepted",
            "summary": "Accepted summary",
            "completed_at": "2026-04-20T00:00:00+00:00",
            "metadata": {
                "thread_id": "thread-accepted",
                "snapshot_lifecycle": "accepted",
                "accepted_memory": {
                    "reasoning_state": {"status": "accepted"},
                    "accepted_facts": [{"summary": "accepted fact"}],
                    "root_cause_assessment": {
                        "primary_root_cause": "Accepted root cause",
                        "summary": "Accepted root cause summary.",
                    },
                },
            },
        },
        "sess-published": {
            "id": "sess-published",
            "summary": "Published summary",
            "completed_at": "2026-04-19T00:00:00+00:00",
            "metadata": {
                "thread_id": "thread-published",
                "memory": {
                    "published": {
                        "reasoning_state": {"status": "published"},
                        "accepted_facts": [{"summary": "published fact"}],
                        "root_cause_assessment": {
                            "primary_root_cause": "Published root cause",
                            "summary": "Published root cause summary.",
                        },
                    }
                },
            },
        },
    }
    agent_store.get_session.side_effect = lambda session_id: sessions.get(session_id)

    service = CaseMemoryService(case_store=case_store, agent_store=agent_store)

    result = service.get_case_memory("case-priority")

    assert result["latest_session_id"] == "sess-published"
    assert result["thread_id"] == "thread-published"
    assert result["memory_scope"] == "published"
    assert result["authoritative_memory_scope"] == "published"
    assert result["authoritative_snapshot"]["reasoning_state"]["status"] == "published"
    assert result["memory_snapshot"] == result["authoritative_snapshot"]
    assert "accepted_snapshot" not in result
    assert result["memory_lifecycle"] == "published"
    assert result["memory_is_authoritative"] is True
    assert "compatibility_aliases" not in result
    assert result["summary"] == "Published root cause summary."


def test_get_case_memory_preserves_legacy_metadata_fallback():
    case_store = MagicMock()
    agent_store = MagicMock()
    case_store.get_case.return_value = {
        "workflows": [{"session_id": "sess-3"}],
        "events": [],
    }
    agent_store.get_session.return_value = {
        "id": "sess-3",
        "summary": "Legacy summary",
        "metadata": {
            "thread_id": "thread-3",
            "reasoning_state": {"status": "legacy"},
            "accepted_facts": [{"summary": "legacy fact"}],
            "root_cause_assessment": {
                "primary_root_cause": "Legacy root cause",
                "summary": "Legacy root cause summary.",
            },
        },
    }

    service = CaseMemoryService(case_store=case_store, agent_store=agent_store)

    result = service.get_case_memory("case-3")

    assert result["memory_scope"] is None
    assert result["authoritative_memory_scope"] is None
    assert result["authoritative_snapshot"]["reasoning_state"]["status"] == "legacy"
    assert result["authoritative_snapshot"]["accepted_facts"][0]["summary"] == "legacy fact"
    assert result["authoritative_snapshot"]["root_cause_assessment"]["primary_root_cause"] == "Legacy root cause"
    assert result["memory_snapshot"] == result["authoritative_snapshot"]
    assert "accepted_snapshot" not in result
    assert result["memory_lifecycle"] is None
    assert result["memory_kind"] == "working_context"
    assert result["memory_is_authoritative"] is False
    assert result["publication_scope"] == "legacy"
    assert "compatibility_aliases" not in result
    assert result["summary"] == "Legacy root cause summary."
    assert result["authoritative_snapshot"]["memory_scope"] is None
    assert result["authoritative_snapshot"]["authoritative_memory_scope"] is None
    assert result["authoritative_snapshot"]["memory_kind"] == "working_context"
    assert result["authoritative_snapshot"]["memory_is_authoritative"] is False
    assert result["authoritative_snapshot"]["publication_scope"] == "legacy"
    assert result["authoritative_snapshot"]["memory_boundary"] == result["memory_boundary"]


def test_record_reasoning_checkpoint_does_not_materialize_accepted_memory_for_working_lifecycle():
    case_store = MagicMock()
    service = CaseMemoryService(case_store=case_store, agent_store=MagicMock())

    service.record_reasoning_checkpoint(
        case_id="case-working",
        session_id="sess-working",
        terminal_status=None,
        thread_id="thread-working",
        snapshot_lifecycle="working",
        investigation_plan={"lane": "ioc"},
        deterministic_decision={"verdict": "UNKNOWN"},
        reasoning_state={"status": "collecting_evidence", "hypotheses": []},
        entity_summary={"relationships": []},
        evidence_summary={"timeline": [], "edges": []},
        root_cause_assessment={},
        accepted_facts=[{"summary": "working fact"}],
        unresolved_questions=["What is missing?"],
    )

    assert case_store.add_event.call_count == 1
    payload = case_store.add_event.call_args.kwargs["payload"]
    assert payload["snapshot_lifecycle"] == "working"
    assert payload["memory_scope"] is None
    assert payload["authoritative_memory_scope"] is None
    assert payload["memory_kind"] == "working_context"
    assert payload["memory_is_authoritative"] is False
    assert "accepted_memory" not in payload
    assert payload.get("memory") is None
    assert payload["checkpoint_contract"]["case_memory_scope"] is None
    assert payload["checkpoint_contract"]["authoritative_memory_scope"] is None
    assert payload["checkpoint_contract"]["memory_kind"] == "working_context"
    assert payload["checkpoint_contract"]["memory_is_authoritative"] is False
    assert payload["checkpoint_contract"]["publication_scope"] == "working"
    assert payload["checkpoint_contract"]["case_memory_publication_ready"] is False
    assert payload["checkpoint_contract"]["accepted_fact_solidification_ready"] is False
    assert payload["checkpoint_contract"]["root_cause_solidification_ready"] is False
    assert payload["memory_boundary"]["publication_scope"] == "working"
    assert payload["checkpoint_contract"]["thread_publication_allowed"] is False


def test_record_reasoning_checkpoint_materializes_published_and_accepted_memory_for_published_lifecycle():
    case_store = MagicMock()
    service = CaseMemoryService(case_store=case_store, agent_store=MagicMock())

    service.record_reasoning_checkpoint(
        case_id="case-published",
        session_id="sess-published",
        terminal_status="completed",
        thread_id="thread-published",
        snapshot_lifecycle="published",
        investigation_plan={"lane": "log_identity"},
        deterministic_decision={"verdict": "SUSPICIOUS"},
        reasoning_state={"status": "sufficient_evidence", "hypotheses": []},
        entity_summary={"relationships": [{"id": "rel-1"}]},
        evidence_summary={"timeline": [{"summary": "Observed auth event"}], "edges": [{"id": "edge-1"}]},
        root_cause_assessment={
            "primary_root_cause": "Published root cause",
            "summary": "Published root cause summary.",
        },
        accepted_facts=[{"summary": "published fact"}],
        unresolved_questions=[],
    )

    first_payload = case_store.add_event.call_args_list[0].kwargs["payload"]
    second_payload = case_store.add_event.call_args_list[1].kwargs["payload"]

    for payload in (first_payload, second_payload):
        assert payload["snapshot_lifecycle"] == "published"
        assert payload["memory_scope"] == "published"
        assert payload["authoritative_memory_scope"] == "published"
        assert payload["memory_kind"] == "authoritative_case_truth"
        assert payload["memory_is_authoritative"] is True
        assert payload["accepted_memory"]["accepted_facts"][0]["summary"] == "published fact"
        assert payload["authoritative_memory"]["accepted_facts"][0]["summary"] == "published fact"
        assert payload["memory"]["accepted"]["accepted_facts"][0]["summary"] == "published fact"
        assert payload["memory"]["published"]["root_cause_assessment"]["primary_root_cause"] == "Published root cause"
        assert payload["checkpoint_contract"]["case_memory_scope"] == "published"
        assert payload["checkpoint_contract"]["authoritative_memory_scope"] == "published"
        assert payload["checkpoint_contract"]["memory_kind"] == "authoritative_case_truth"
        assert payload["checkpoint_contract"]["memory_is_authoritative"] is True
        assert payload["checkpoint_contract"]["publication_scope"] == "published"
        assert payload["checkpoint_contract"]["case_memory_publication_ready"] is True
        assert payload["checkpoint_contract"]["accepted_fact_solidification_ready"] is True
        assert payload["checkpoint_contract"]["root_cause_solidification_ready"] is True
        assert payload["accepted_memory"]["memory_boundary"]["publication_scope"] == "published"
        assert payload["accepted_memory"]["case_scope"]["case_id"] == "case-published"


def test_record_reasoning_checkpoint_materializes_only_accepted_memory_for_accepted_lifecycle():
    case_store = MagicMock()
    service = CaseMemoryService(case_store=case_store, agent_store=MagicMock())

    service.record_reasoning_checkpoint(
        case_id="case-accepted",
        session_id="sess-accepted",
        terminal_status="completed",
        thread_id="thread-accepted",
        snapshot_lifecycle="accepted",
        investigation_plan={"lane": "email"},
        deterministic_decision={"verdict": "SUSPICIOUS"},
        reasoning_state={"status": "sufficient_evidence", "hypotheses": []},
        entity_summary={"relationships": [{"id": "rel-accepted"}]},
        evidence_summary={"timeline": [{"summary": "Observed delivery evidence"}], "edges": [{"id": "edge-accepted"}]},
        root_cause_assessment={
            "primary_root_cause": "Accepted root cause",
            "summary": "Accepted root cause summary.",
        },
        accepted_facts=[{"summary": "accepted fact"}],
        unresolved_questions=[],
    )

    first_payload = case_store.add_event.call_args_list[0].kwargs["payload"]
    second_payload = case_store.add_event.call_args_list[1].kwargs["payload"]

    for payload in (first_payload, second_payload):
        assert payload["snapshot_lifecycle"] == "accepted"
        assert payload["memory_scope"] == "accepted"
        assert payload["authoritative_memory_scope"] == "accepted"
        assert payload["memory_kind"] == "authoritative_case_truth"
        assert payload["memory_is_authoritative"] is True
        assert payload["accepted_memory"]["accepted_facts"][0]["summary"] == "accepted fact"
        assert payload["authoritative_memory"]["accepted_facts"][0]["summary"] == "accepted fact"
        assert payload["memory"]["accepted"]["root_cause_assessment"]["primary_root_cause"] == "Accepted root cause"
        assert "published" not in payload["memory"]
        assert payload["checkpoint_contract"]["case_memory_scope"] == "accepted"
        assert payload["checkpoint_contract"]["memory_kind"] == "authoritative_case_truth"
        assert payload["checkpoint_contract"]["memory_is_authoritative"] is True
        assert payload["checkpoint_contract"]["publication_scope"] == "accepted"
        assert payload["checkpoint_contract"]["case_memory_publication_ready"] is True
        assert payload["checkpoint_contract"]["accepted_fact_solidification_ready"] is True
        assert payload["checkpoint_contract"]["root_cause_solidification_ready"] is True
        assert payload["accepted_memory"]["memory_boundary"]["publication_scope"] == "accepted"
        assert payload["checkpoint_contract"]["thread_publication_allowed"] is True


def test_record_reasoning_checkpoint_does_not_emit_root_cause_event_before_publication_ready():
    case_store = MagicMock()
    service = CaseMemoryService(case_store=case_store, agent_store=MagicMock())

    service.record_reasoning_checkpoint(
        case_id="case-candidate",
        session_id="sess-candidate",
        terminal_status=None,
        thread_id="thread-candidate",
        snapshot_lifecycle="candidate",
        investigation_plan={"lane": "log_identity"},
        deterministic_decision={"verdict": "SUSPICIOUS"},
        reasoning_state={"status": "collecting_evidence", "hypotheses": []},
        entity_summary={"relationships": [{"id": "rel-1"}]},
        evidence_summary={"timeline": [{"summary": "Observed auth event"}], "edges": [{"id": "edge-1"}]},
        root_cause_assessment={
            "primary_root_cause": "Candidate root cause",
            "summary": "Candidate root cause summary.",
        },
        accepted_facts=[{"summary": "candidate fact"}],
        unresolved_questions=["Need more evidence"],
    )

    assert case_store.add_event.call_count == 1
    payload = case_store.add_event.call_args.kwargs["payload"]
    assert payload["snapshot_lifecycle"] == "candidate"
    assert payload["memory_scope"] is None
    assert payload["authoritative_memory_scope"] is None
    assert payload["memory_kind"] == "working_context"
    assert payload["memory_is_authoritative"] is False
    assert payload["checkpoint_contract"]["memory_kind"] == "working_context"
    assert payload["checkpoint_contract"]["memory_is_authoritative"] is False
    assert payload["checkpoint_contract"]["publication_scope"] == "candidate"
    assert payload["checkpoint_contract"]["case_memory_publication_ready"] is False
    assert payload["checkpoint_contract"]["accepted_fact_solidification_ready"] is False
    assert payload["checkpoint_contract"]["root_cause_solidification_ready"] is False
    assert "accepted_memory" not in payload
    assert payload.get("memory") is None