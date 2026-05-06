import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_store import AgentStore
from src.agent.investigation_workdir import InvestigationWorkdirService
from src.web.app import create_app


def _isolated_app(tmp_path, monkeypatch):
    workdir_root = tmp_path / "workdirs"
    monkeypatch.setenv("CABTA_INVESTIGATION_WORKDIR", str(workdir_root))
    app = create_app()
    app.state.agent_store = AgentStore(db_path=str(tmp_path / "agent.db"))
    app.state.investigation_workdir_service = InvestigationWorkdirService(base_dir=workdir_root)
    if app.state.agent_loop is not None:
        app.state.agent_loop.store = app.state.agent_store
        app.state.agent_loop.investigation_workdir_service = app.state.investigation_workdir_service
    return app


def _session_with_workdir(app, tmp_path):
    session_id = app.state.agent_store.create_session(
        "Investigate suspicious domain",
        metadata={
            "investigation_workdir": {"investigation_id": "runtime-session"},
            "context_ledger_latest": {"ledger_id": "led-runtime", "objective": "decide_next_tool", "authoritative_for_verdict": False},
            "context_ledgers": [{"ledger_id": "led-runtime", "included_count": 2, "authoritative_for_verdict": False}],
            "context_pack_summary_latest": {"pack_id": "ctx-runtime", "ledger_id": "led-runtime", "authoritative_for_verdict": False},
            "context_budget_latest": {"estimated_total": 123, "over_budget": False},
        },
    )
    service = app.state.investigation_workdir_service
    service.create_or_get("runtime-session", session_id=session_id, case_id="case-1")
    service.write_json("runtime-session", "artifacts/reports/summary.json", {"ok": True}, artifact_kind="report")
    service.write_text("runtime-session", "artifacts/reports/notes.md", "# Notes\n", artifact_kind="report")
    service.write_text("runtime-session", "artifacts/uploads/sample.bin", "binary-ish", artifact_kind="upload")
    return session_id


def test_create_app_wires_investigation_workdir_service_and_agent_loop(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)

    assert app.state.investigation_workdir_service is not None
    assert app.state.agent_loop is not None
    assert app.state.agent_loop.investigation_workdir_service is app.state.investigation_workdir_service
    assert str(app.state.investigation_workdir_service.base_dir).endswith("workdirs")


def test_workdir_api_summary_artifacts_safe_read_and_archive(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    session_id = _session_with_workdir(app, tmp_path)
    client = TestClient(app)

    summary = client.get(f"/api/agent/sessions/{session_id}/workdir")
    assert summary.status_code == 200
    assert summary.json()["investigation_id"] == "runtime-session"

    artifacts = client.get(f"/api/agent/sessions/{session_id}/workdir/artifacts")
    assert artifacts.status_code == 200
    assert any(item["relative_path"] == "artifacts/reports/summary.json" for item in artifacts.json()["artifacts"])

    json_artifact = client.get(f"/api/agent/sessions/{session_id}/workdir/artifacts/artifacts/reports/summary.json")
    assert json_artifact.status_code == 200
    assert json_artifact.json()["content"] == {"ok": True}

    text_artifact = client.get(f"/api/agent/sessions/{session_id}/workdir/artifacts/artifacts/reports/notes.md")
    assert text_artifact.status_code == 200
    assert "# Notes" in text_artifact.text

    unsupported = client.get(f"/api/agent/sessions/{session_id}/workdir/artifacts/artifacts/uploads/sample.bin")
    assert unsupported.status_code == 415
    assert "Only text" in unsupported.json()["detail"]

    encoded_traversal = client.get(f"/api/agent/sessions/{session_id}/workdir/artifacts/%2e%2e/outside.txt")
    assert encoded_traversal.status_code == 400
    assert "Unsafe artifact path" in encoded_traversal.json()["detail"]

    archive = client.post(f"/api/agent/sessions/{session_id}/workdir/archive")
    assert archive.status_code == 200
    assert archive.json()["archive"]["filename"].endswith(".zip")

    download = client.get(f"/api/agent/sessions/{session_id}/workdir/archive/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/zip")
    assert len(download.content) > 0


def test_context_ledger_api_exposes_non_authoritative_history(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    session_id = _session_with_workdir(app, tmp_path)
    client = TestClient(app)

    response = client.get(f"/api/agent/sessions/{session_id}/context-ledger")

    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "context-ledger-history/v1"
    assert payload["authority"] == "context_audit_metadata_non_authoritative"
    assert payload["authoritative_for_verdict"] is False
    assert payload["latest_ledger"]["ledger_id"] == "led-runtime"
    assert payload["ledgers"][0]["authoritative_for_verdict"] is False
    assert payload["workdir_artifacts"]["context_ledger_latest"].endswith("context_ledger_latest.json")


def test_workdir_validation_review_and_resume_api(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    session_id = _session_with_workdir(app, tmp_path)
    client = TestClient(app)

    validation = client.get(f"/api/agent/sessions/{session_id}/workdir/validation")
    assert validation.status_code == 200
    assert validation.json()["valid"] is True

    review = client.get(f"/api/agent/sessions/{session_id}/workdir/review")
    assert review.status_code == 200
    assert review.json()["decision"] == "pending"

    updated = client.put(
        f"/api/agent/sessions/{session_id}/workdir/review",
        json={"decision": "accepted", "reviewer": "analyst-web", "notes": "Evidence reviewed."},
    )
    assert updated.status_code == 200
    assert updated.json()["decision"] == "accepted"
    assert updated.json()["reviewer"] == "analyst-web"

    resume = client.get(f"/api/agent/sessions/{session_id}/workdir/resume")
    assert resume.status_code == 200
    assert resume.json()["metadata"]["source_workdir_investigation_id"] == "runtime-session"
    assert resume.json()["metadata"]["source_workdir_id"] == "runtime-session"
    assert resume.json()["metadata"]["source_case_id"] == "case-1"
    assert resume.json()["source_workdir_id"] == "runtime-session"
    assert resume.json()["source_case_id"] == "case-1"
    assert resume.json()["resume_authority"] == "workdir_mirror_non_authoritative"


def test_workdir_api_returns_clear_404_for_unknown_session_or_workdir(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    session_id = app.state.agent_store.create_session(
        "Investigate missing workdir",
        metadata={"investigation_workdir": {"investigation_id": "missing-workdir"}},
    )
    client = TestClient(app)

    unknown_session = client.get("/api/agent/sessions/no-such-session/workdir")
    assert unknown_session.status_code == 404
    assert unknown_session.json()["detail"] == "Session not found"

    missing_workdir = client.get(f"/api/agent/sessions/{session_id}/workdir")
    assert missing_workdir.status_code == 404
    assert missing_workdir.json()["detail"] == "Investigation workdir not found"

    missing_archive = client.get(f"/api/agent/sessions/{session_id}/workdir/archive/download")
    assert missing_archive.status_code == 404
    assert missing_archive.json()["detail"] == "Investigation workdir not found"


def test_agent_ui_pages_expose_workdir_links(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    _session_with_workdir(app, tmp_path)
    client = TestClient(app)

    investigations = client.get("/agent/investigations")
    assert investigations.status_code == 200
    assert "Workdir Export & Review" in investigations.text
    assert "/workdir/archive/download" in investigations.text
    assert "/workdir/artifacts/review.md" in investigations.text

    chat = client.get("/agent/chat")
    assert chat.status_code == 200
    assert "Workdir Export" in chat.text
    assert "workdirArchiveLink" in chat.text
    assert "Context Ledger Audit" in chat.text
    assert "/context-ledger" in chat.text
    assert "/workdir/artifacts/review.md" in chat.text
    assert "/workdir/validation" in chat.text
    assert "/workdir/review" in chat.text
    assert "/workdir/resume" in chat.text
    assert "Resume Payload" in chat.text
    assert "Resume Start" in chat.text
    assert "Workdir export ready" in chat.text
    assert "renderWorkdirExportReadyBubble" in chat.text
    assert "data-session-id" in chat.text
    assert "non-authoritative workdir mirror" in chat.text
    assert "non-authoritative context ledger audit metadata" in chat.text
    assert "fresh AISA tools must re-validate" in chat.text
    assert "/workdir/resume/start" in chat.text


def test_workdir_resume_start_route_uses_agent_loop_and_preserves_boundary(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    session_id = _session_with_workdir(app, tmp_path)

    class FakeAgentLoop:
        def __init__(self):
            self.calls = []

        async def resume_from_workdir(self, investigation_id, *, goal=None, case_id=None, max_steps=None):
            self.calls.append({
                "investigation_id": investigation_id,
                "goal": goal,
                "case_id": case_id,
                "max_steps": max_steps,
            })
            return {
                "session_id": "resumed-session",
                "status": "active",
                "restored": True,
                "resume_payload": {
                    "resume_authority": "workdir_mirror_non_authoritative",
                },
            }

    fake_loop = FakeAgentLoop()
    app.state.agent_loop = fake_loop
    client = TestClient(app)

    response = client.post(
        f"/api/agent/sessions/{session_id}/workdir/resume/start",
        json={"goal": "Resume with fresh validation", "case_id": "case-2", "max_steps": 3},
    )

    assert response.status_code == 200
    assert response.json()["session_id"] == "resumed-session"
    assert response.json()["resume_payload"]["resume_authority"] == "workdir_mirror_non_authoritative"
    assert fake_loop.calls == [
        {
            "investigation_id": "runtime-session",
            "goal": "Resume with fresh validation",
            "case_id": "case-2",
            "max_steps": 3,
        }
    ]


def test_workdir_api_degrades_when_service_missing(tmp_path, monkeypatch):
    app = _isolated_app(tmp_path, monkeypatch)
    session_id = app.state.agent_store.create_session("Investigate", metadata={})
    app.state.investigation_workdir_service = None
    client = TestClient(app)

    response = client.get(f"/api/agent/sessions/{session_id}/workdir")

    assert response.status_code == 503
    assert "not initialized" in response.json()["detail"]
