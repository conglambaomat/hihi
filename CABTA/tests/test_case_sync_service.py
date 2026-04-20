import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.case_sync_service import CaseSyncService


@pytest.fixture
def sample_state():
    return SimpleNamespace(
        thread_id="thread-1",
        investigation_plan={"lane": "log_identity"},
        deterministic_decision={"verdict": "SUSPICIOUS"},
        reasoning_state={
            "status": "collecting_evidence",
            "hypotheses": [
                {"statement": "Hypothesis A"},
                {"statement": "Hypothesis B"},
            ],
        },
        entity_state={"entities": {"user:alice": {"id": "user:alice", "type": "user", "value": "alice"}}},
        evidence_state={"timeline": [{"summary": "Observed auth event"}], "edges": [{"id": "edge-1"}]},
        accepted_facts=[
            {"summary": "Fact 1"},
            {"summary": "Fact 2"},
        ],
        snapshot_lifecycle="published",
        unresolved_questions=["Which host is affected?"],
        agentic_explanation={
            "root_cause_assessment": {
                "primary_root_cause": "Suspicious credential use",
                "summary": "Most evidence supports suspicious credential use.",
            }
        },
    )


def test_sync_reasoning_checkpoint_uses_case_memory_service(sample_state):
    case_memory_service = MagicMock()
    entity_resolver = MagicMock()
    evidence_graph = MagicMock()
    entity_resolver.summarize_for_case_event.return_value = {"relationships": [{"id": "rel-1"}]}
    evidence_graph.summarize_for_case_event.return_value = {
        "timeline": [{"summary": "Observed auth event"}],
        "edges": [{"id": "edge-1"}],
    }

    service = CaseSyncService(
        case_store=None,
        case_memory_service=case_memory_service,
        entity_resolver=entity_resolver,
        evidence_graph=evidence_graph,
    )

    service.sync_reasoning_checkpoint(
        case_id="case-1",
        session_id="sess-1",
        state=sample_state,
        terminal_status="completed",
    )

    case_memory_service.record_reasoning_checkpoint.assert_called_once()
    kwargs = case_memory_service.record_reasoning_checkpoint.call_args.kwargs
    assert kwargs["case_id"] == "case-1"
    assert kwargs["session_id"] == "sess-1"
    assert kwargs["thread_id"] == "thread-1"
    assert kwargs["terminal_status"] == "completed"
    assert kwargs["investigation_plan"] == {"lane": "log_identity"}
    assert kwargs["deterministic_decision"] == {"verdict": "SUSPICIOUS"}
    assert kwargs["root_cause_assessment"]["primary_root_cause"] == "Suspicious credential use"
    assert kwargs["snapshot_lifecycle"] == "published"
    assert kwargs["checkpoint_metrics"]["accepted_fact_count"] == 2
    assert kwargs["checkpoint_metrics"]["hypothesis_count"] == 2
    assert kwargs["checkpoint_summary"]["has_root_cause"] is True
    assert kwargs["checkpoint_summary"]["reasoning_status"] == "collecting_evidence"
    assert kwargs["checkpoint_summary"]["case_memory_scope"] == "published"
    assert kwargs["checkpoint_summary"]["case_memory_publication_ready"] is True


def test_sync_reasoning_checkpoint_falls_back_to_case_store(sample_state):
    case_store = MagicMock()
    entity_resolver = MagicMock()
    evidence_graph = MagicMock()
    entity_resolver.summarize_for_case_event.return_value = {"relationships": [{"id": "rel-1"}]}
    evidence_graph.summarize_for_case_event.return_value = {
        "timeline": [{"summary": "Observed auth event"}],
        "edges": [{"id": "edge-1"}],
    }

    service = CaseSyncService(
        case_store=case_store,
        case_memory_service=None,
        entity_resolver=entity_resolver,
        evidence_graph=evidence_graph,
    )

    service.sync_reasoning_checkpoint(
        case_id="case-2",
        session_id="sess-2",
        state=sample_state,
        terminal_status="failed",
    )

    assert case_store.add_event.call_count == 2

    first_call = case_store.add_event.call_args_list[0]
    assert first_call.args[0] == "case-2"
    assert first_call.kwargs["event_type"] == "agentic_reasoning_checkpoint"
    assert first_call.kwargs["payload"]["thread_id"] == "thread-1"
    assert first_call.kwargs["payload"]["snapshot_lifecycle"] == "published"
    assert first_call.kwargs["payload"]["case_memory_scope"] == "published"
    assert first_call.kwargs["payload"]["case_memory_publication_ready"] is True
    assert first_call.kwargs["payload"]["accepted_facts"] == sample_state.accepted_facts[-12:]
    assert first_call.kwargs["payload"]["checkpoint_metrics"]["accepted_fact_count"] == 2
    assert first_call.kwargs["payload"]["checkpoint_metrics"]["evidence_timeline_count"] == 1
    assert first_call.kwargs["payload"]["checkpoint_summary"]["has_root_cause"] is True

    second_call = case_store.add_event.call_args_list[1]
    assert second_call.kwargs["event_type"] == "root_cause_assessment"
    assert second_call.kwargs["payload"]["snapshot_lifecycle"] == "published"
    assert second_call.kwargs["payload"]["root_cause_assessment"]["primary_root_cause"] == "Suspicious credential use"
    assert second_call.kwargs["payload"]["checkpoint_summary"]["terminal_status"] == "failed"
    assert second_call.kwargs["payload"]["checkpoint_summary"]["case_memory_scope"] == "published"
    assert second_call.kwargs["payload"]["checkpoint_summary"]["case_memory_publication_ready"] is True


def test_sync_reasoning_checkpoint_does_not_emit_root_cause_event_before_case_memory_publication_ready(sample_state):
    case_store = MagicMock()
    entity_resolver = MagicMock()
    evidence_graph = MagicMock()
    entity_resolver.summarize_for_case_event.return_value = {"relationships": [{"id": "rel-1"}]}
    evidence_graph.summarize_for_case_event.return_value = {
        "timeline": [{"summary": "Observed auth event"}],
        "edges": [{"id": "edge-1"}],
    }
    sample_state.snapshot_lifecycle = "candidate"

    service = CaseSyncService(
        case_store=case_store,
        case_memory_service=None,
        entity_resolver=entity_resolver,
        evidence_graph=evidence_graph,
    )

    service.sync_reasoning_checkpoint(
        case_id="case-candidate",
        session_id="sess-candidate",
        state=sample_state,
        terminal_status=None,
    )

    assert case_store.add_event.call_count == 1
    payload = case_store.add_event.call_args.kwargs["payload"]
    assert payload["snapshot_lifecycle"] == "candidate"
    assert payload["case_memory_scope"] is None
    assert payload["case_memory_publication_ready"] is False
    assert payload["checkpoint_summary"]["has_root_cause"] is True


def test_sync_reasoning_checkpoint_returns_early_without_case_id(sample_state):
    case_store = MagicMock()
    service = CaseSyncService(case_store=case_store, case_memory_service=None, entity_resolver=None, evidence_graph=None)

    service.sync_reasoning_checkpoint(
        case_id=None,
        session_id="sess-3",
        state=sample_state,
        terminal_status=None,
    )

    case_store.add_event.assert_not_called()
