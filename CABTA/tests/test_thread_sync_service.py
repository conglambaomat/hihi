import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.thread_sync_service import ThreadSyncService


@pytest.fixture
def sample_state():
    return SimpleNamespace(
        session_id="sess-1",
        case_id="case-1",
        thread_id="thread-1",
        step_count=3,
        investigation_plan={"lane": "ioc"},
        reasoning_state={"open_questions": ["What host is impacted?"], "status": "collecting_evidence"},
        entity_state={"entities": {"ip:1.2.3.4": {"id": "ip:1.2.3.4", "type": "ip", "value": "1.2.3.4"}}},
        evidence_state={"timeline": [{"summary": "IOC seen in logs"}]},
        deterministic_decision={"verdict": "SUSPICIOUS"},
        agentic_explanation={"root_cause_assessment": {"summary": "Most evidence supports malicious infrastructure use."}},
        active_observations=[{"summary": "Obs1"}, {"summary": "Obs2"}],
        accepted_facts=[{"summary": "Fact1"}, {"summary": "Fact2"}],
        unresolved_questions=["Which host is impacted?"],
        evidence_quality_summary={"observation_count": 2, "average_quality": 0.81},
        is_terminal=lambda: False,
    )


def test_build_thread_snapshot_returns_expected_shape(sample_state):
    service = ThreadSyncService(thread_store=None, store=None, notify=None)

    snapshot = service.build_thread_snapshot(sample_state)

    assert snapshot["snapshot_state"] == "working"
    assert snapshot["investigation_plan"] == {"lane": "ioc"}
    assert snapshot["reasoning_state"]["status"] == "collecting_evidence"
    assert snapshot["deterministic_decision"]["verdict"] == "SUSPICIOUS"
    assert snapshot["root_cause_assessment"]["summary"] == "Most evidence supports malicious infrastructure use."
    assert len(snapshot["active_observations"]) == 2
    assert len(snapshot["accepted_facts"]) == 2
    assert snapshot["working_memory"]["active_observations"] == snapshot["active_observations"]
    assert snapshot["accepted_memory"]["accepted_facts"] == snapshot["accepted_facts"]
    assert snapshot["snapshot_metrics"]["active_observation_count"] == 2
    assert snapshot["snapshot_metrics"]["accepted_fact_count"] == 2
    assert snapshot["snapshot_metrics"]["unresolved_question_count"] == 1
    assert snapshot["memory_layers"] == {"working": "working_memory", "accepted": "accepted_memory"}
    assert snapshot["thread_context"]["session_id"] == "sess-1"
    assert snapshot["thread_context"]["thread_id"] == "thread-1"
    assert snapshot["thread_context"]["step_count"] == 3
    assert snapshot["thread_context"]["memory_scope"] == "working"
    assert snapshot["memory_boundary"]["case_id"] == "case-1"
    assert snapshot["memory_boundary"]["thread_id"] == "thread-1"
    assert snapshot["case_scope"]["case_id"] == "case-1"


def test_sync_thread_snapshot_updates_store(sample_state):
    thread_store = MagicMock()
    thread_store.update_thread_snapshot.return_value = "snap-1"
    service = ThreadSyncService(thread_store=thread_store, store=None, notify=None)

    snapshot_id = service.sync_thread_snapshot(session_id="sess-1", state=sample_state)

    assert snapshot_id == "snap-1"
    thread_store.update_thread_snapshot.assert_called_once()
    kwargs = thread_store.update_thread_snapshot.call_args.kwargs
    assert kwargs["thread_id"] == "thread-1"
    assert kwargs["last_session_id"] == "sess-1"
    assert kwargs["status"] == "active"
    assert kwargs["snapshot"]["snapshot_state"] == "working"
    assert kwargs["pinned_entities"] == ["ip:1.2.3.4"]
    assert kwargs["pinned_questions"] == ["Which host is impacted?"]


def test_build_thread_snapshot_exposes_candidate_lifecycle_contract(sample_state):
    service = ThreadSyncService(thread_store=None, store=None, notify=None)
    sample_state.snapshot_lifecycle = "candidate"

    snapshot = service.build_thread_snapshot(sample_state)

    assert snapshot["snapshot_state"] == "working"
    assert snapshot["snapshot_lifecycle"] == "candidate"
    assert sample_state.snapshot_lifecycle == "candidate"
    assert snapshot["lifecycle_memory_layers"]["candidate"] == "working_memory"
    assert snapshot["snapshot_contract"]["state_version"] == "thread-snapshot-lifecycle/v1"
    assert snapshot["snapshot_contract"]["lifecycle"] == "candidate"
    assert snapshot["snapshot_contract"]["is_terminal"] is False
    assert snapshot["snapshot_contract"]["publication_ready"] is False


def test_finalize_lifecycle_for_state_normalizes_terminal_defaults():
    completed_state = SimpleNamespace(snapshot_lifecycle=None, is_published=False, is_terminal=lambda: True)
    published_state = SimpleNamespace(snapshot_lifecycle=None, is_published=True, is_terminal=lambda: True)
    active_state = SimpleNamespace(snapshot_lifecycle=None, is_published=False, is_terminal=lambda: False)

    assert ThreadSyncService.finalize_lifecycle_for_state(completed_state) == "accepted"
    assert completed_state.snapshot_lifecycle == "accepted"
    assert ThreadSyncService.finalize_lifecycle_for_state(published_state) == "published"
    assert published_state.snapshot_lifecycle == "published"
    assert ThreadSyncService.finalize_lifecycle_for_state(active_state) == "working"
    assert active_state.snapshot_lifecycle == "working"


def test_sync_thread_snapshot_marks_terminal_state_as_completed():
    thread_store = MagicMock()
    thread_store.update_thread_snapshot.return_value = "snap-terminal"
    state = SimpleNamespace(
        thread_id="thread-terminal",
        session_id="sess-terminal",
        investigation_plan={},
        reasoning_state={},
        entity_state={},
        evidence_state={},
        deterministic_decision={"verdict": "MALICIOUS"},
        agentic_explanation={"root_cause_assessment": {"summary": "Completed assessment."}},
        active_observations=[],
        accepted_facts=[{"summary": "Accepted fact"}],
        unresolved_questions=[],
        evidence_quality_summary={},
        is_terminal=lambda: True,
    )
    service = ThreadSyncService(thread_store=thread_store, store=None, notify=None)

    snapshot_id = service.sync_thread_snapshot(session_id="sess-terminal", state=state)

    assert snapshot_id == "snap-terminal"
    kwargs = thread_store.update_thread_snapshot.call_args.kwargs
    assert kwargs["status"] == "completed"
    assert kwargs["snapshot"]["snapshot_state"] == "accepted"
    assert kwargs["snapshot"]["thread_context"]["memory_scope"] == "accepted"


def test_build_thread_snapshot_promotes_published_lifecycle_when_terminal_and_published():
    service = ThreadSyncService(thread_store=None, store=None, notify=None)
    state = SimpleNamespace(
        thread_id="thread-published",
        session_id="sess-published",
        step_count=7,
        investigation_plan={},
        reasoning_state={"status": "supported"},
        entity_state={},
        evidence_state={},
        deterministic_decision={"verdict": "MALICIOUS"},
        agentic_explanation={"root_cause_assessment": {"summary": "Published assessment."}},
        active_observations=[],
        accepted_facts=[{"summary": "Accepted fact"}],
        unresolved_questions=[],
        evidence_quality_summary={"average_quality": 0.93},
        is_published=True,
        is_terminal=lambda: True,
    )

    snapshot = service.build_thread_snapshot(state)

    assert snapshot["snapshot_state"] == "accepted"
    assert snapshot["snapshot_lifecycle"] == "published"
    assert snapshot["lifecycle_memory_layers"]["published"] == "accepted_memory"
    assert snapshot["snapshot_contract"]["lifecycle"] == "published"
    assert snapshot["snapshot_contract"]["is_terminal"] is True
    assert snapshot["snapshot_contract"]["publication_ready"] is True
    assert snapshot["accepted_memory"]["deterministic_decision"]["verdict"] == "MALICIOUS"
    assert snapshot["thread_context"]["memory_scope"] == "published"
    assert snapshot["memory_boundary"]["thread_id"] == "thread-published"


def test_thread_memory_helpers_support_new_and_legacy_snapshot_shapes():
    new_snapshot = {
        "working_memory": {
            "active_observations": [{"summary": "obs"}],
            "unresolved_questions": ["question"],
            "reasoning_state": {"status": "collecting_evidence"},
            "entity_state": {"entities": {}},
            "evidence_state": {"timeline": []},
        },
        "accepted_memory": {
            "accepted_facts": [{"summary": "fact"}],
            "deterministic_decision": {"verdict": "SUSPICIOUS"},
            "agentic_explanation": {"root_cause_assessment": {"summary": "rca"}},
            "root_cause_assessment": {"summary": "rca"},
            "evidence_quality_summary": {"average_quality": 0.8},
        },
    }
    legacy_snapshot = {
        "active_observations": [{"summary": "legacy-obs"}],
        "unresolved_questions": ["legacy-question"],
        "reasoning_state": {"status": "collecting_evidence"},
        "entity_state": {"entities": {}},
        "evidence_state": {"timeline": []},
        "accepted_facts": [{"summary": "legacy-fact"}],
        "deterministic_decision": {"verdict": "CLEAN"},
        "agentic_explanation": {"root_cause_assessment": {"summary": "legacy-rca"}},
        "root_cause_assessment": {"summary": "legacy-rca"},
        "evidence_quality_summary": {"average_quality": 0.5},
    }

    assert ThreadSyncService.get_working_memory(new_snapshot)["active_observations"][0]["summary"] == "obs"
    assert ThreadSyncService.get_accepted_memory(new_snapshot)["accepted_facts"][0]["summary"] == "fact"
    assert ThreadSyncService.get_working_memory(legacy_snapshot)["active_observations"][0]["summary"] == "legacy-obs"
    assert ThreadSyncService.get_accepted_memory(legacy_snapshot)["accepted_facts"][0]["summary"] == "legacy-fact"


def test_consume_pending_thread_command_updates_state_and_store(sample_state):
    thread_store = MagicMock()
    store = MagicMock()
    notify = MagicMock()
    thread_store.claim_next_command.return_value = {
        "id": "cmd-1",
        "content": "Check adjacent host telemetry",
        "intent": "follow_up",
        "created_at": "2026-04-19T10:00:00Z",
        "payload": {
            "intent": "follow_up",
            "requires_fresh_evidence": True,
        },
    }

    service = ThreadSyncService(thread_store=thread_store, store=store, notify=notify)

    def dedupe_text(values):
        seen = set()
        result = []
        for value in values:
            key = str(value).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(str(value).strip())
        return result

    consumed = service.consume_pending_thread_command(
        session_id="sess-1",
        state=sample_state,
        dedupe_text=dedupe_text,
    )

    assert consumed is True
    assert sample_state.unresolved_questions[0] == "Check adjacent host telemetry"
    assert sample_state.reasoning_state["open_questions"][0] == "Check adjacent host telemetry"
    store.update_session_metadata.assert_called_once()
    store.add_step.assert_called_once()
    thread_store.complete_command.assert_called_once()
    notify.assert_called_once()


def test_consume_pending_thread_command_returns_false_without_command(sample_state):
    thread_store = MagicMock()
    thread_store.claim_next_command.return_value = None
    service = ThreadSyncService(thread_store=thread_store, store=MagicMock(), notify=MagicMock())

    consumed = service.consume_pending_thread_command(
        session_id="sess-1",
        state=sample_state,
        dedupe_text=lambda values: values,
    )

    assert consumed is False