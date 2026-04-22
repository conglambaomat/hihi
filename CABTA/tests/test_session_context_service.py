import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.session_context_service import SessionContextService


@pytest.fixture
def sample_state():
    return SimpleNamespace(
        session_id="sess-1",
        case_id="case-1",
        thread_id="thread-1",
        step_count=2,
        investigation_plan={"lane": "ioc"},
        reasoning_state={},
        entity_state={},
        evidence_state={},
        active_observations=[],
        accepted_facts=[],
        unresolved_questions=[],
        evidence_quality_summary={},
        fact_family_schemas={},
        restored_memory_scope=None,
        chat_context_restored_memory_scope=None,
        session_snapshot_id=None,
        agentic_explanation={"root_cause_assessment": {"status": "supported"}},
    )


def test_restore_state_from_snapshot_populates_state(sample_state):
    snapshot = {
        "investigation_plan": {"lane": "email"},
        "reasoning_state": {"status": "collecting_evidence"},
        "entity_state": {"entities": {"ip:1.2.3.4": {"value": "1.2.3.4"}}},
        "evidence_state": {"timeline": [{"summary": "event"}]},
        "active_observations": [{"summary": "obs"}],
        "accepted_facts": [{"summary": "fact"}],
        "unresolved_questions": ["What host was involved?"],
        "evidence_quality_summary": {"average_quality": 0.9},
        "fact_family_schemas": {"log": {"version": "fact-family/log/v1"}},
    }

    memory_scope = SessionContextService.restore_state_from_snapshot(sample_state, snapshot)

    assert memory_scope is None
    assert sample_state.investigation_plan == {"lane": "email"}
    assert sample_state.reasoning_state["status"] == "collecting_evidence"
    assert sample_state.entity_state["entities"]["ip:1.2.3.4"]["value"] == "1.2.3.4"
    assert sample_state.evidence_state["timeline"][0]["summary"] == "event"
    assert sample_state.active_observations[0]["summary"] == "obs"
    assert sample_state.accepted_facts[0]["summary"] == "fact"
    assert sample_state.unresolved_questions == ["What host was involved?"]
    assert sample_state.evidence_quality_summary["average_quality"] == 0.9
    assert sample_state.fact_family_schemas["log"]["version"] == "fact-family/log/v1"
    assert sample_state.restored_memory_scope is None
    assert sample_state.chat_context_restored_memory_scope is None
    assert sample_state.restored_memory_is_authoritative is False
    assert sample_state.chat_context_restored_memory_is_authoritative is False


def test_restore_state_from_snapshot_prefers_published_memory_scope(sample_state):
    snapshot = {
        "memory": {
            "accepted": {
                "reasoning_state": {"status": "accepted"},
                "accepted_facts": [{"summary": "accepted fact"}],
            },
            "published": {
                "reasoning_state": {"status": "published"},
                "accepted_facts": [{"summary": "published fact"}],
            },
        }
    }

    memory_scope = SessionContextService.restore_state_from_snapshot(sample_state, snapshot)

    assert memory_scope == "published"
    assert sample_state.reasoning_state["status"] == "published"
    assert sample_state.accepted_facts[0]["summary"] == "published fact"


def test_restore_state_from_snapshot_falls_back_to_published_memory_scope(sample_state):
    snapshot = {
        "memory": {
            "published": {
                "reasoning_state": {"status": "published"},
                "accepted_facts": [{"summary": "published fact"}],
            }
        }
    }

    memory_scope = SessionContextService.restore_state_from_snapshot(sample_state, snapshot)

    assert memory_scope == "published"
    assert sample_state.reasoning_state["status"] == "published"
    assert sample_state.accepted_facts[0]["summary"] == "published fact"


def test_build_chat_context_flags_prefers_metadata_and_restored_state(sample_state):
    service = SessionContextService(store=None, thread_store=None)
    sample_state.active_observations = [{"summary": "obs"}]
    sample_state.chat_context_restored_memory_scope = "published"
    sample_state.restored_memory_is_authoritative = True

    result = service.build_chat_context_flags(
        state=sample_state,
        metadata={
            "chat_context_restored": True,
            "chat_follow_up_requires_fresh_evidence": False,
            "chat_context_restored_memory_scope": "accepted",
            "chat_context_restored_memory_is_authoritative": False,
        },
    )

    assert result == {
        "chat_context_restored": True,
        "requires_fresh_evidence": False,
        "restored_memory_scope": "accepted",
        "restored_memory_is_authoritative": True,
        "has_context_state": True,
    }


def test_restore_state_from_snapshot_rejects_cross_thread_memory_boundary(sample_state):
    snapshot = {
        "memory": {
            "published": {
                "memory_boundary": {
                    "case_id": "case-1",
                    "thread_id": "thread-other",
                    "session_id": "sess-foreign",
                    "publication_scope": "published",
                },
                "reasoning_state": {"status": "foreign-thread"},
            }
        }
    }

    memory_scope = SessionContextService.restore_state_from_snapshot(
        sample_state,
        snapshot,
        expected_case_id="case-1",
        expected_thread_id="thread-1",
    )

    assert memory_scope is None
    assert sample_state.reasoning_state == {}


def test_restore_state_from_snapshot_rejects_cross_case_payload(sample_state):
    snapshot = {
        "case_id": "case-other",
        "reasoning_state": {"status": "wrong-case"},
    }

    memory_scope = SessionContextService.restore_state_from_snapshot(
        sample_state,
        snapshot,
        expected_case_id="case-1",
        expected_thread_id="thread-1",
    )

    assert memory_scope is None
    assert sample_state.reasoning_state == {}


def test_resolve_thread_id_prefers_requested_thread():
    store = MagicMock()
    thread_store = MagicMock()
    thread_store.ensure_thread.return_value = "thread-x"
    service = SessionContextService(store=store, thread_store=thread_store)

    thread_id = service.resolve_thread_id(
        session_id="sess-1",
        case_id="case-1",
        metadata={"thread_id": "thread-x"},
    )

    assert thread_id == "thread-x"
    thread_store.ensure_thread.assert_called_once()


def test_restore_follow_up_context_uses_thread_snapshot(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {
        "metadata": {
            "thread_id": "thread-1",
        }
    }
    thread_store.get_latest_accepted_snapshot.return_value = {}
    thread_store.get_latest_snapshot.return_value = {
        "snapshot_id": "snap-1",
        "snapshot": {
            "reasoning_state": {"status": "restored"},
            "active_observations": [{"summary": "restored obs"}],
        },
    }
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={"chat_parent_session_id": "parent-1", "thread_id": "thread-1", "case_id": "case-1"},
    )

    assert restored is True
    assert sample_state.reasoning_state["status"] == "restored"
    assert sample_state.session_snapshot_id == "snap-1"
    thread_store.get_latest_accepted_snapshot.assert_called_once_with("thread-1")
    thread_store.get_latest_snapshot.assert_called_once_with("thread-1")
    store.update_session_metadata.assert_called_once()
    args = store.update_session_metadata.call_args.args
    assert args[1]["chat_context_restored_source"] == "thread_snapshot"
    assert args[1]["chat_context_restored_counts"]["active_observation_count"] == 1
    assert args[1]["chat_context_restored_reasoning_status"] == "restored"


def test_restore_follow_up_context_prefers_lifecycle_accepted_thread_truth(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {
        "metadata": {
            "thread_id": "thread-1",
        }
    }
    thread_store.get_latest_accepted_snapshot.return_value = {
        "snapshot_id": "snap-accepted",
        "snapshot": {
            "snapshot_lifecycle": "published",
            "case_id": "case-1",
            "thread_id": "thread-1",
            "accepted_memory": {
                "reasoning_state": {"status": "published-thread-memory"},
                "accepted_facts": [{"summary": "published thread fact"}],
            },
        },
    }
    thread_store.get_latest_snapshot.return_value = {
        "snapshot_id": "snap-working",
        "snapshot": {
            "snapshot_lifecycle": "working",
            "working_memory": {
                "reasoning_state": {"status": "working-thread-memory"},
                "accepted_facts": [{"summary": "working thread fact"}],
            },
        },
    }
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={"chat_parent_session_id": "parent-1", "thread_id": "thread-1", "case_id": "case-1"},
    )

    assert restored is True
    assert sample_state.reasoning_state["status"] == "published-thread-memory"
    assert sample_state.accepted_facts[0]["summary"] == "published thread fact"
    assert sample_state.session_snapshot_id == "snap-accepted"
    thread_store.get_latest_accepted_snapshot.assert_called_once_with("thread-1")
    thread_store.get_latest_snapshot.assert_not_called()
    args = store.update_session_metadata.call_args.args
    assert args[1]["chat_context_restored_memory_scope"] == "published"
    assert args[1]["chat_context_restored_memory_is_authoritative"] is True
    assert args[1]["chat_context_restored_memory_kind"] == "authoritative_case_truth"
    assert args[1]["chat_context_restored_source"] == "thread_snapshot"


def test_restore_follow_up_context_records_memory_scope_from_case_memory(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {"metadata": {}}
    thread_store.get_latest_accepted_snapshot.return_value = {}
    thread_store.get_latest_snapshot.return_value = {}
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={
            "chat_parent_session_id": "parent-1",
            "case_id": "case-1",
            "case_memory_context": {
                "latest_session_id": "sess-prev",
                "authoritative_memory_scope": "published",
                "memory_snapshot": {
                    "case_id": "case-1",
                    "thread_id": "thread-1",
                    "authoritative_memory_scope": "published",
                    "memory": {
                        "published": {
                            "reasoning_state": {"status": "published-memory"},
                            "accepted_facts": [{"summary": "published memory fact"}],
                        }
                    }
                },
            },
        },
    )

    assert restored is True
    assert sample_state.reasoning_state["status"] == "published-memory"
    args = store.update_session_metadata.call_args.args
    kwargs = store.update_session_metadata.call_args.kwargs
    assert kwargs["merge"] is True
    assert args[1]["chat_context_restored_memory_scope"] == "published"
    assert args[1]["chat_context_restored_memory_is_authoritative"] is True
    assert args[1]["chat_context_restored_memory_kind"] == "authoritative_case_truth"
    assert args[1]["chat_context_restored_source"] == "case_memory"
    assert args[1]["chat_context_restored_counts"]["accepted_fact_count"] == 1
    assert args[1]["chat_context_restored_reasoning_status"] == "published-memory"
    assert sample_state.restored_memory_scope == "published"
    assert sample_state.chat_context_restored_memory_scope == "published"
    assert sample_state.restored_memory_is_authoritative is True
    assert sample_state.chat_context_restored_memory_is_authoritative is True


def test_restore_follow_up_context_uses_memory_boundary_session_id_when_case_memory_session_missing(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {"metadata": {}}
    thread_store.get_latest_accepted_snapshot.return_value = {}
    thread_store.get_latest_snapshot.return_value = {}
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={
            "chat_parent_session_id": "parent-1",
            "case_id": "case-1",
            "case_memory_context": {
                "authoritative_memory_scope": "published",
                "memory_snapshot": {
                    "case_id": "case-1",
                    "thread_id": "thread-1",
                    "authoritative_memory_scope": "published",
                    "memory": {
                        "published": {
                            "memory_boundary": {
                                "case_id": "case-1",
                                "thread_id": "thread-1",
                                "session_id": "sess-boundary",
                                "publication_scope": "published",
                            },
                            "reasoning_state": {"status": "published-memory"},
                            "accepted_facts": [{"summary": "published memory fact"}],
                        }
                    },
                },
            },
        },
    )

    assert restored is True
    assert sample_state.session_snapshot_id == "sess-boundary"
    args = store.update_session_metadata.call_args.args
    assert args[1]["chat_context_restored_snapshot_id"] == "sess-boundary"


def test_restore_follow_up_context_falls_back_to_case_memory(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {"metadata": {}}
    thread_store.get_latest_accepted_snapshot.return_value = {}
    thread_store.get_latest_snapshot.return_value = {}
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={
            "chat_parent_session_id": "parent-1",
            "case_id": "case-1",
            "case_memory_context": {
                "latest_session_id": "sess-prev",
                "authoritative_memory_scope": "accepted",
                "accepted_snapshot": {
                    "case_id": "case-1",
                    "thread_id": "thread-1",
                    "authoritative_memory_scope": "accepted",
                    "reasoning_state": {"status": "case_memory"},
                    "accepted_facts": [{"summary": "accepted"}],
                },
            },
        },
    )

    assert restored is True
    assert sample_state.reasoning_state["status"] == "case_memory"
    assert sample_state.session_snapshot_id == "sess-prev"
    assert sample_state.restored_memory_scope == "accepted"
    assert sample_state.restored_memory_is_authoritative is True
    args = store.update_session_metadata.call_args.args
    assert args[1]["chat_context_restored_source"] == "case_memory"
    assert args[1]["chat_context_restored_memory_scope"] == "accepted"
    assert args[1]["chat_context_restored_memory_is_authoritative"] is True
    assert args[1]["chat_context_restored_counts"]["accepted_fact_count"] == 1


def test_restore_follow_up_context_counts_accepted_facts_only_as_restored_context(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {"metadata": {}}
    thread_store.get_latest_accepted_snapshot.return_value = {}
    thread_store.get_latest_snapshot.return_value = {}
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={
            "chat_parent_session_id": "parent-1",
            "case_id": "case-1",
            "case_memory_context": {
                "latest_session_id": "sess-prev",
                "authoritative_memory_scope": "accepted",
                "accepted_snapshot": {
                    "case_id": "case-1",
                    "thread_id": "thread-1",
                    "authoritative_memory_scope": "accepted",
                    "accepted_facts": [{"summary": "accepted-only fact"}],
                },
            },
        },
    )

    assert restored is True
    assert sample_state.accepted_facts == [{"summary": "accepted-only fact"}]
    assert sample_state.restored_memory_scope == "accepted"
    assert sample_state.restored_memory_is_authoritative is True
    args = store.update_session_metadata.call_args.args
    assert args[1]["chat_context_restored"] is True
    assert args[1]["chat_context_restored_memory_scope"] == "accepted"
    assert args[1]["chat_context_restored_memory_is_authoritative"] is True
    assert args[1]["chat_context_restored_counts"]["accepted_fact_count"] == 1
    assert args[1]["chat_context_restored_source"] == "case_memory"
    assert args[1]["chat_context_restored_fact_family_schemas"] == {}


def test_restore_follow_up_context_rejects_thread_snapshot_from_other_case(sample_state):
    store = MagicMock()
    thread_store = MagicMock()
    store.get_session.return_value = {
        "case_id": "case-1",
        "metadata": {
            "thread_id": "thread-1",
        }
    }
    thread_store.get_latest_accepted_snapshot.return_value = {
        "snapshot_id": "snap-foreign",
        "snapshot": {
            "case_id": "case-other",
            "thread_id": "thread-1",
            "reasoning_state": {"status": "foreign"},
        },
    }
    thread_store.get_latest_snapshot.return_value = {}
    service = SessionContextService(store=store, thread_store=thread_store)

    restored = service.restore_follow_up_context(
        session_id="sess-2",
        state=sample_state,
        metadata={"chat_parent_session_id": "parent-1", "thread_id": "thread-1", "case_id": "case-1"},
    )

    assert restored is False
    assert sample_state.reasoning_state == {}
    args = store.update_session_metadata.call_args.args
    assert args[1]["chat_context_restored_source"] == "none"


def test_maybe_record_thread_user_message_records_chat_messages(sample_state):
    thread_store = MagicMock()
    service = SessionContextService(store=MagicMock(), thread_store=thread_store)

    service.maybe_record_thread_user_message(
        state=sample_state,
        metadata={
            "chat_mode": True,
            "chat_user_message": "Please investigate this IOC",
            "chat_parent_session_id": "parent-1",
            "chat_intent": "follow_up",
        },
    )

    thread_store.append_message.assert_called_once()
    kwargs = thread_store.append_message.call_args.kwargs
    assert kwargs["thread_id"] == "thread-1"
    assert kwargs["role"] == "user"
    assert kwargs["content"] == "Please investigate this IOC"


def test_record_thread_assistant_message_records_assistant_output(sample_state):
    thread_store = MagicMock()
    service = SessionContextService(store=MagicMock(), thread_store=thread_store)

    service.record_thread_assistant_message(
        state=sample_state,
        content="Suspicious infrastructure identified.",
    )

    thread_store.append_message.assert_called_once()
    kwargs = thread_store.append_message.call_args.kwargs
    assert kwargs["thread_id"] == "thread-1"
    assert kwargs["role"] == "assistant"
    assert kwargs["content"] == "Suspicious infrastructure identified."