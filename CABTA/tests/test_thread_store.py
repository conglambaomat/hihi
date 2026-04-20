import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.thread_store import ThreadStore


def test_get_thread_exposes_neutral_thread_snapshot_without_accepted_alias(tmp_path):
    store = ThreadStore(db_path=str(tmp_path / "threads.db"))
    thread_id = store.create_thread(case_id="case-1", root_session_id="sess-1")
    snapshot = {
        "snapshot_state": "accepted",
        "snapshot_lifecycle": "published",
        "snapshot_contract": {
            "lifecycle": "published",
            "state_version": "thread-snapshot-lifecycle/v1",
        },
        "accepted_memory": {
            "accepted_facts": [{"summary": "published fact"}],
        },
    }

    store.update_thread_snapshot(
        thread_id=thread_id,
        snapshot=snapshot,
        last_session_id="sess-2",
        pinned_entities=["ip:1.2.3.4"],
        pinned_questions=["What host is impacted?"],
        status="completed",
    )

    thread = store.get_thread(thread_id)

    assert thread["last_thread_snapshot"]["snapshot_lifecycle"] == "published"
    assert thread["last_thread_snapshot_lifecycle"] == "published"
    assert thread["last_thread_snapshot_authority_scope"] == "published"
    assert "last_accepted_snapshot" not in thread
    assert thread["pinned_entities"] == ["ip:1.2.3.4"]
    assert thread["pinned_questions"] == ["What host is impacted?"]


def test_get_latest_snapshot_exposes_authority_scope_and_lifecycle(tmp_path):
    store = ThreadStore(db_path=str(tmp_path / "threads.db"))
    thread_id = store.create_thread(case_id="case-2", root_session_id="sess-1")
    snapshot = {
        "snapshot_state": "accepted",
        "snapshot_lifecycle": "published",
        "snapshot_contract": {
            "lifecycle": "published",
            "state_version": "thread-snapshot-lifecycle/v1",
        },
        "accepted_memory": {
            "accepted_facts": [{"summary": "published fact"}],
        },
    }

    snapshot_id = store.update_thread_snapshot(
        thread_id=thread_id,
        snapshot=snapshot,
        last_session_id="sess-2",
        status="completed",
    )

    latest = store.get_latest_snapshot(thread_id)

    assert latest["snapshot_id"] == snapshot_id
    assert latest["authority_scope"] == "published"
    assert latest["snapshot_lifecycle"] == "published"
    assert latest["snapshot"]["snapshot_state"] == "accepted"


def test_get_latest_snapshot_falls_back_to_accepted_authority_from_snapshot_state(tmp_path):
    store = ThreadStore(db_path=str(tmp_path / "threads.db"))
    thread_id = store.create_thread(case_id="case-3", root_session_id="sess-1")
    snapshot = {
        "snapshot_state": "accepted",
        "accepted_memory": {
            "accepted_facts": [{"summary": "accepted fact"}],
        },
    }

    store.update_thread_snapshot(
        thread_id=thread_id,
        snapshot=snapshot,
        last_session_id="sess-2",
        status="completed",
    )

    latest = store.get_latest_snapshot(thread_id)

    assert latest["authority_scope"] == "accepted"
    assert latest["snapshot_lifecycle"] is None
    assert latest["snapshot"]["accepted_memory"]["accepted_facts"][0]["summary"] == "accepted fact"


def test_get_latest_accepted_snapshot_returns_published_or_accepted_thread_truth(tmp_path):
    store = ThreadStore(db_path=str(tmp_path / "threads.db"))
    thread_id = store.create_thread(case_id="case-4", root_session_id="sess-1")
    snapshot = {
        "snapshot_state": "accepted",
        "snapshot_lifecycle": "published",
        "snapshot_contract": {
            "lifecycle": "published",
            "state_version": "thread-snapshot-lifecycle/v1",
        },
        "accepted_memory": {
            "accepted_facts": [{"summary": "published fact"}],
        },
    }

    snapshot_id = store.update_thread_snapshot(
        thread_id=thread_id,
        snapshot=snapshot,
        last_session_id="sess-2",
        status="completed",
    )

    accepted = store.get_latest_accepted_snapshot(thread_id)

    assert accepted["snapshot_id"] == snapshot_id
    assert accepted["authority_scope"] == "published"
    assert accepted["snapshot"]["accepted_memory"]["accepted_facts"][0]["summary"] == "published fact"


def test_get_latest_accepted_snapshot_does_not_alias_working_snapshot_as_accepted_truth(tmp_path):
    store = ThreadStore(db_path=str(tmp_path / "threads.db"))
    thread_id = store.create_thread(case_id="case-5", root_session_id="sess-1")
    snapshot = {
        "snapshot_state": "working",
        "snapshot_lifecycle": "working",
        "snapshot_contract": {
            "lifecycle": "working",
            "state_version": "thread-snapshot-lifecycle/v1",
        },
        "accepted_memory": {
            "accepted_facts": [{"summary": "not yet accepted"}],
        },
    }

    store.update_thread_snapshot(
        thread_id=thread_id,
        snapshot=snapshot,
        last_session_id="sess-2",
        status="active",
    )

    latest = store.get_latest_snapshot(thread_id)
    accepted = store.get_latest_accepted_snapshot(thread_id)

    assert latest["authority_scope"] == "working"
    assert accepted == {}
