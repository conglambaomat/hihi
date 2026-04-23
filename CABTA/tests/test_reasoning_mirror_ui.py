from fastapi.testclient import TestClient

from src.web.app import create_app


def test_agent_investigations_page_contains_reasoning_mirror_hooks():
    client = TestClient(create_app())

    response = client.get("/agent/investigations")

    assert response.status_code == 200
    assert "buildSessionReasoningTab" in response.text
    assert "Deterministic Decision" in response.text
    assert "Missing Evidence / Next Pivots" in response.text


def test_case_detail_page_contains_reasoning_rollup_card():
    client = TestClient(create_app())
    create_response = client.post(
        "/api/cases",
        json={"title": "Reasoning Mirror Case", "description": "UI smoke", "severity": "medium"},
    )
    case_id = create_response.json()["id"]

    response = client.get(f"/cases/{case_id}")

    assert response.status_code == 200
    assert "Investigation Reasoning" in response.text
    assert 'id="caseReasoningPanels"' in response.text


def test_case_reasoning_api_returns_rollup_for_existing_case():
    client = TestClient(create_app())
    create_response = client.post(
        "/api/cases",
        json={"title": "Reasoning API Case", "description": "API smoke", "severity": "high"},
    )
    case_id = create_response.json()["id"]

    response = client.get(f"/api/cases/{case_id}/reasoning")

    assert response.status_code == 200
    payload = response.json()
    assert payload["case_id"] == case_id
    assert "deterministic_decision" in payload
    assert "agentic_explanation" in payload
    assert "reasoning_state" in payload
    assert "entity_state" in payload
    assert "reasoning_truth" in payload
    assert payload["reasoning_truth"]["source"] == "selected_workflow_metadata"
    assert payload["reasoning_truth"]["selected_session_matches_root_cause_checkpoint"] is False
    assert payload["reasoning_truth"]["root_cause_checkpoint_session_id"] is None
    assert "memory_kind" in payload["reasoning_truth"]
    assert "authoritative_memory_scope" in payload["reasoning_truth"]
    assert "memory_boundary" in payload["reasoning_truth"]
    assert "memory_kind" in payload
    assert "publication_scope" in payload
    assert "authoritative_memory_scope" in payload
    assert "memory_scope" in payload
    assert "timeline_summary" in payload


def test_case_reasoning_api_prefers_root_cause_checkpoint_contract_when_same_session_is_selected():
    client = TestClient(create_app())
    create_response = client.post(
        "/api/cases",
        json={"title": "Reasoning Contract Case", "description": "checkpoint contract", "severity": "high"},
    )
    case_id = create_response.json()["id"]
    app = client.app

    session_id = app.state.agent_store.create_session(
        goal="Investigate phishing delivery",
        case_id=case_id,
    )
    app.state.agent_store.update_session_metadata(
        session_id,
        {
            "deterministic_decision": {"verdict": "MALICIOUS", "score": 88, "severity": "high"},
            "reasoning_state": {"status": "supported", "hypotheses": [{"id": "hyp-1"}]},
            "entity_state": {"entities": {"user:alice": {"id": "user:alice"}}},
        },
        merge=True,
    )
    app.state.case_store.link_workflow(case_id, session_id, "wf-phishing")
    app.state.case_store.add_event(
        case_id,
        event_type="root_cause_assessment",
        title="Root cause assessment updated",
        payload={
            "session_id": session_id,
            "publication_scope": "published",
            "authoritative_memory_scope": "published",
            "memory_kind": "authoritative_case_truth",
            "memory_is_authoritative": True,
            "memory_boundary": {
                "case_id": case_id,
                "session_id": session_id,
                "thread_id": "thread-phishing",
                "publication_scope": "published",
            },
            "root_cause_assessment": {
                "primary_root_cause": "Phishing email delivered the payload.",
                "summary": "Phishing delivery is the strongest explanation.",
            },
        },
    )

    response = client.get(f"/api/cases/{case_id}/reasoning")

    assert response.status_code == 200
    payload = response.json()
    assert payload["latest_session_id"] == session_id
    assert payload["reasoning_truth"] == {
        "source": "selected_workflow_metadata",
        "selected_session_matches_root_cause_checkpoint": True,
        "root_cause_checkpoint_session_id": session_id,
        "memory_scope": "published",
        "memory_kind": "authoritative_case_truth",
        "publication_scope": "published",
        "authoritative_memory_scope": "published",
        "memory_is_authoritative": True,
        "memory_boundary": {
            "case_id": case_id,
            "session_id": session_id,
            "thread_id": "thread-phishing",
            "publication_scope": "published",
        },
    }
    assert payload["thread_id"] == "thread-phishing"
    assert payload["memory_scope"] == "published"
    assert payload["memory_kind"] == "authoritative_case_truth"
    assert payload["publication_scope"] == "published"
    assert payload["authoritative_memory_scope"] == "published"
    assert payload["memory_is_authoritative"] is True
