from fastapi.testclient import TestClient

from src.web.app import create_app


def test_agent_chat_page_exposes_reasoning_panels():
    client = TestClient(create_app())

    response = client.get("/agent/chat")

    assert response.status_code == 200
    assert 'Deterministic Decision' in response.text
    assert 'Agentic Explanation' in response.text
    assert 'Hypotheses' in response.text
    assert 'Entity Pivots' in response.text
    assert 'Missing Evidence / Next Pivots' in response.text
    assert 'id="deterministicDecisionPanel"' in response.text
    assert 'id="agenticExplanationPanel"' in response.text
    assert 'id="hypothesesPanel"' in response.text
    assert 'id="entityPivotsPanel"' in response.text
    assert 'id="missingEvidencePanel"' in response.text
    assert "/api/agent/investigate" not in response.text
    assert "body: JSON.stringify({ message: text })" in response.text
    assert "if (data.session_id && data.session_id !== sessionId)" in response.text
    assert "switchSession(data.session_id);" in response.text
