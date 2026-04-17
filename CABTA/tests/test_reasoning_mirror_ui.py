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
    assert "timeline_summary" in payload
