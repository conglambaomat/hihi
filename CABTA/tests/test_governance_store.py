import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.governance_store import GovernanceStore


def test_record_decision_feedback_persists_structured_event(tmp_path):
    db_path = tmp_path / "governance.db"
    store = GovernanceStore(db_path=str(db_path))

    decision_id = store.log_ai_decision(
        session_id="sess-1",
        case_id="case-1",
        workflow_id="wf-1",
        decision_type="root_cause",
        summary="Suspected credential theft chain",
        rationale="Evidence supports suspicious login then mailbox access.",
    )

    feedback_id = store.record_decision_feedback(
        decision_id=decision_id,
        session_id="sess-1",
        case_id="case-1",
        workflow_id="wf-1",
        feedback_type="root_cause_correctness",
        verdict="incorrect",
        target={"entity_type": "user", "entity_value": "alice@example.com"},
        useful=False,
        comment="Root cause was actually token theft, not password spray.",
        metadata={"false_positive_chain": True},
        reviewer="analyst-a",
    )

    assert feedback_id

    events = store.list_decision_feedback(decision_id=decision_id)
    assert len(events) == 1
    event = events[0]
    assert event["id"] == feedback_id
    assert event["decision_id"] == decision_id
    assert event["feedback_type"] == "root_cause_correctness"
    assert event["verdict"] == "incorrect"
    assert event["target"] == {"entity_type": "user", "entity_value": "alice@example.com"}
    assert event["useful"] == 0
    assert event["metadata"] == {"false_positive_chain": True}
    assert event["reviewer"] == "analyst-a"


def test_add_decision_feedback_bridges_legacy_columns_and_structured_event(tmp_path):
    db_path = tmp_path / "governance.db"
    store = GovernanceStore(db_path=str(db_path))

    decision_id = store.log_ai_decision(
        session_id="sess-2",
        decision_type="pivot_selection",
        summary="Pivot to WHOIS and passive DNS",
        rationale="Need stronger infrastructure evidence.",
    )

    updated = store.add_decision_feedback(
        decision_id,
        feedback="Correct pivot, useful for confirming infrastructure overlap.",
        reviewer="analyst-b",
    )

    assert updated is True

    decision = store.get_ai_decision(decision_id)
    assert decision is not None
    assert decision["feedback"] == "Correct pivot, useful for confirming infrastructure overlap."
    assert decision["feedback_reviewer"] == "analyst-b"
    assert decision["feedback_at"] is not None

    events = store.list_decision_feedback(decision_id=decision_id)
    assert len(events) == 1
    event = events[0]
    assert event["feedback_type"] == "decision_review"
    assert event["verdict"] == "correct"
    assert event["comment"] == "Correct pivot, useful for confirming infrastructure overlap."
    assert event["metadata"] == {
        "legacy_feedback_text": "Correct pivot, useful for confirming infrastructure overlap."
    }


def test_list_decision_feedback_filters_by_session_case_and_type(tmp_path):
    db_path = tmp_path / "governance.db"
    store = GovernanceStore(db_path=str(db_path))

    decision_a = store.log_ai_decision(
        session_id="sess-a",
        case_id="case-a",
        decision_type="entity_link",
        summary="Linked alice to host-1",
    )
    decision_b = store.log_ai_decision(
        session_id="sess-b",
        case_id="case-b",
        decision_type="pivot_selection",
        summary="Pivot to sandbox detonation",
    )

    store.record_decision_feedback(
        decision_id=decision_a,
        session_id="sess-a",
        case_id="case-a",
        feedback_type="entity_link_correctness",
        verdict="correct",
        reviewer="analyst-a",
    )
    store.record_decision_feedback(
        decision_id=decision_b,
        session_id="sess-b",
        case_id="case-b",
        feedback_type="pivot_utility",
        useful=True,
        reviewer="analyst-b",
    )

    assert len(store.list_decision_feedback(session_id="sess-a")) == 1
    assert len(store.list_decision_feedback(case_id="case-b")) == 1
    filtered = store.list_decision_feedback(feedback_type="pivot_utility")
    assert len(filtered) == 1
    assert filtered[0]["decision_id"] == decision_b


def test_governance_summary_aggregates_approvals_decisions_and_feedback_by_scope(tmp_path):
    db_path = tmp_path / "governance.db"
    store = GovernanceStore(db_path=str(db_path))

    approval_pending = store.create_approval(
        session_id="sess-1",
        case_id="case-1",
        workflow_id="wf-1",
        action_type="block_indicator",
        tool_name="firewall_block",
        target={"ip": "1.2.3.4"},
        rationale="High-confidence malicious IP.",
    )
    approval_reviewed = store.create_approval(
        session_id="sess-1",
        case_id="case-1",
        workflow_id="wf-1",
        action_type="disable_account",
        tool_name="iam_disable_user",
        target={"user": "alice@example.com"},
        rationale="Confirmed compromised account.",
    )
    store.review_approval(approval_reviewed, approved=True, reviewer="analyst-z")

    decision_id = store.log_ai_decision(
        session_id="sess-1",
        case_id="case-1",
        workflow_id="wf-1",
        decision_type="root_cause",
        summary="Token theft likely led to mailbox access.",
    )
    store.record_decision_feedback(
        decision_id=decision_id,
        session_id="sess-1",
        case_id="case-1",
        workflow_id="wf-1",
        feedback_type="root_cause_correctness",
        verdict="correct",
        reviewer="analyst-z",
    )

    store.log_ai_decision(
        session_id="sess-2",
        case_id="case-2",
        workflow_id="wf-2",
        decision_type="pivot_selection",
        summary="Pivot to passive DNS.",
    )

    summary = store.governance_summary(session_id="sess-1", case_id="case-1")

    assert summary["scope"] == {"session_id": "sess-1", "case_id": "case-1"}
    assert summary["approvals"]["total"] == 2
    assert summary["approvals"]["pending"] == 1
    assert summary["approvals"]["by_status"]["pending"] == 1
    assert summary["approvals"]["by_status"]["approved"] == 1
    assert summary["ai_decisions"]["total"] == 1
    assert summary["ai_decisions"]["by_type"]["root_cause"] == 1
    assert summary["decision_feedback"]["total"] == 1
    assert summary["decision_feedback"]["by_type"]["root_cause_correctness"] == 1
    assert summary["decision_feedback"]["by_verdict"]["correct"] == 1
