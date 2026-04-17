from __future__ import annotations

from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from src.agent.agent_store import AgentStore
from src.case_intelligence.service import CaseIntelligenceService
from src.web.analysis_manager import AnalysisManager
from src.web.app import create_app
from src.web.case_store import CaseStore


def _build_isolated_app(tmp_path):
    app = create_app()

    analysis_manager = AnalysisManager(db_path=str(tmp_path / "jobs.db"))
    case_store = CaseStore(db_path=str(tmp_path / "cases.db"))
    agent_store = AgentStore(db_path=str(tmp_path / "agent.db"))

    app.state.analysis_manager = analysis_manager
    app.state.case_store = case_store
    app.state.agent_store = agent_store
    app.state.case_intelligence = CaseIntelligenceService(
        analysis_manager=analysis_manager,
        agent_store=agent_store,
        case_store=case_store,
        governance_store=app.state.governance_store,
    )

    if app.state.mcp_client is not None:
        app.state.mcp_client.agent_store = agent_store
    if app.state.agent_loop is not None:
        app.state.agent_loop.store = agent_store
        app.state.agent_loop.case_store = case_store
        app.state.agent_loop._active_sessions.clear()
        app.state.agent_loop._approval_events.clear()
        app.state.agent_loop._subscribers.clear()
    if app.state.playbook_engine is not None:
        app.state.playbook_engine.agent_store = agent_store
        app.state.playbook_engine.agent_loop = app.state.agent_loop
    if app.state.workflow_service is not None:
        app.state.workflow_service.agent_store = agent_store
        app.state.workflow_service.case_store = case_store

    return app


def _seed_reasoning_session(
    app,
    *,
    case_id: str,
    goal: str,
    workflow_id: str,
    agent_profile_id: str,
    deterministic_decision: dict,
    root_cause_assessment: dict,
    reasoning_state: dict,
    entity_state: dict,
    summary: str,
    status: str = "completed",
):
    metadata = {
        "workflow_id": workflow_id,
        "agent_profile_id": agent_profile_id,
        "deterministic_decision": deterministic_decision,
        "deterministic_decision_output": deterministic_decision,
        "agentic_explanation": {
            "root_cause_assessment": root_cause_assessment,
            "reasoning_status": root_cause_assessment.get("status", reasoning_state.get("status", "collecting_evidence")),
            "explanation_confidence": root_cause_assessment.get("confidence"),
            "causal_chain": list(root_cause_assessment.get("causal_chain", [])),
            "missing_evidence": list(root_cause_assessment.get("missing_evidence", [])),
            "recommended_next_pivots": ["Pivot on the associated user, host, and session."],
            "recommended_next_actions": ["Validate containment and confirm user impact."],
        },
        "agentic_explanation_output": {
            "root_cause_assessment": root_cause_assessment,
            "reasoning_status": root_cause_assessment.get("status", reasoning_state.get("status", "collecting_evidence")),
            "explanation_confidence": root_cause_assessment.get("confidence"),
            "causal_chain": list(root_cause_assessment.get("causal_chain", [])),
            "missing_evidence": list(root_cause_assessment.get("missing_evidence", [])),
            "recommended_next_pivots": ["Pivot on the associated user, host, and session."],
            "recommended_next_actions": ["Validate containment and confirm user impact."],
        },
        "root_cause_assessment": root_cause_assessment,
        "reasoning_state": reasoning_state,
        "entity_state": entity_state,
        "evidence_state": {
            "timeline": [
                {
                    "type": "tool_observation",
                    "timestamp": "2026-04-17T00:00:00+00:00",
                    "summary": "Evidence tied the suspicious activity to the primary hypothesis.",
                }
            ],
            "edges": [
                {
                    "source": "hypothesis:primary",
                    "target": "evidence:step-1",
                    "relation": "supports",
                }
            ],
        },
    }

    session_id = app.state.agent_store.create_session(goal=goal, case_id=case_id, metadata=metadata)
    app.state.agent_store.update_session_metadata(session_id, metadata)
    app.state.agent_store.update_session_findings(
        session_id,
        [
            {
                "type": "tool_result",
                "tool": "search_logs",
                "result": {
                    "verdict": deterministic_decision.get("verdict"),
                    "severity": deterministic_decision.get("severity"),
                },
            },
            {
                "type": "final_answer",
                "answer": summary,
                "deterministic_decision": deterministic_decision,
                "agentic_explanation": metadata["agentic_explanation"],
                "root_cause_assessment": root_cause_assessment,
                "entity_state": entity_state,
                "evidence_state": metadata["evidence_state"],
            },
        ],
    )
    app.state.agent_store.update_session_status(session_id, status, summary)
    app.state.case_store.link_workflow(case_id, session_id, workflow_id)
    app.state.case_store.add_event(
        case_id,
        event_type="root_cause_assessment",
        title=root_cause_assessment.get("summary") or "Root cause updated",
        payload={
            "session_id": session_id,
            "root_cause_assessment": root_cause_assessment,
            "deterministic_decision": deterministic_decision,
            "entity_summary": {
                "entity_count": len(entity_state.get("entities", {})),
                "relationships": entity_state.get("relationships", []),
            },
        },
    )
    return session_id


def test_analyst_follow_up_flow_mirrors_reasoning_across_chat_investigations_and_case_detail(tmp_path):
    app = _build_isolated_app(tmp_path)
    client = TestClient(app)

    create_case = client.post(
        "/api/cases",
        json={"title": "Analyst workflow case", "description": "E2E reasoning flow", "severity": "high"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["id"]

    initial_session = _seed_reasoning_session(
        app,
        case_id=case_id,
        goal="Investigate account-securecheck.com phishing infrastructure",
        workflow_id="wf-phishing-initial",
        agent_profile_id="phishing_analyst",
        deterministic_decision={
            "score": 91,
            "severity": "high",
            "verdict": "MALICIOUS",
            "confidence": 0.9,
            "policy_flags": ["needs_review"],
        },
        root_cause_assessment={
            "primary_root_cause": "Phishing email delivered a malicious link to the user.",
            "summary": "Initial evidence points to phishing-based delivery and execution.",
            "status": "supported",
            "confidence": 0.84,
            "causal_chain": [
                "Malicious email delivered to alice",
                "alice clicked the phishing link",
                "The payload contacted suspicious infrastructure",
            ],
            "missing_evidence": ["Confirm email delivery logs for the original message."],
        },
        reasoning_state={
            "status": "supported",
            "hypotheses": [
                {
                    "id": "hyp-initial",
                    "statement": "A phishing email initiated the malicious activity.",
                    "status": "supported",
                    "confidence": 0.84,
                    "supporting_evidence_refs": [{"tool_name": "search_logs", "step_number": 1}],
                    "contradicting_evidence_refs": [],
                    "open_questions": ["What host executed the payload?"],
                }
            ],
            "missing_evidence": ["Confirm email delivery logs for the original message."],
        },
        entity_state={
            "entities": {
                "user:alice": {"id": "user:alice", "type": "user", "value": "alice", "label": "alice"},
                "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12", "label": "WS-12"},
                "ip:185.220.101.45": {
                    "id": "ip:185.220.101.45",
                    "type": "ip",
                    "value": "185.220.101.45",
                    "label": "185.220.101.45",
                },
            },
            "relationships": [
                {"source": "user:alice", "target": "host:ws-12", "relation": "uses_host"},
                {"source": "host:ws-12", "target": "ip:185.220.101.45", "relation": "linked_to"},
            ],
        },
        summary="Initial investigation completed with phishing as the leading root cause.",
    )

    chat_page = client.get(f"/agent/chat?session={initial_session}")
    assert chat_page.status_code == 200
    assert "Deterministic Decision" in chat_page.text
    assert "Agentic Explanation" in chat_page.text
    assert "fetch('/api/chat'" in chat_page.text
    assert "fetch('/api/agent/sessions/' + encodeURIComponent(sessionKey))" in chat_page.text

    async def fake_follow_up_investigate(goal, case_id=None, playbook_id=None, max_steps=None, metadata=None):
        return _seed_reasoning_session(
            app,
            case_id=case_id,
            goal=goal,
            workflow_id="wf-phishing-followup",
            agent_profile_id=(metadata or {}).get("agent_profile_id") or "phishing_analyst",
            deterministic_decision={
                "score": 96,
                "severity": "critical",
                "verdict": "MALICIOUS",
                "confidence": 0.96,
                "policy_flags": ["contains_user_impact", "needs_containment"],
            },
            root_cause_assessment={
                "primary_root_cause": "alice executed the phishing payload on WS-12, leading to outbound C2 activity.",
                "summary": "Follow-up pivots tied the malicious infrastructure directly to alice on WS-12.",
                "status": "supported",
                "confidence": 0.91,
                "causal_chain": [
                    "Phishing email delivered to alice",
                    "alice executed the payload on WS-12",
                    "WS-12 beaconed to 185.220.101.45",
                ],
                "missing_evidence": ["Collect final mailbox headers to preserve delivery evidence."],
            },
            reasoning_state={
                "status": "supported",
                "hypotheses": [
                    {
                        "id": "hyp-follow-up",
                        "statement": "alice on WS-12 executed the phishing payload that established C2.",
                        "status": "supported",
                        "confidence": 0.91,
                        "supporting_evidence_refs": [{"tool_name": "search_logs", "step_number": 2}],
                        "contradicting_evidence_refs": [],
                        "open_questions": ["Was there lateral movement after the initial beacon?"],
                    }
                ],
                "missing_evidence": ["Collect final mailbox headers to preserve delivery evidence."],
            },
            entity_state={
                "entities": {
                    "user:alice": {"id": "user:alice", "type": "user", "value": "alice", "label": "alice"},
                    "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12", "label": "WS-12"},
                    "ip:185.220.101.45": {
                        "id": "ip:185.220.101.45",
                        "type": "ip",
                        "value": "185.220.101.45",
                        "label": "185.220.101.45",
                    },
                    "session:logon-22": {
                        "id": "session:logon-22",
                        "type": "session",
                        "value": "LOGON-22",
                        "label": "LOGON-22",
                    },
                },
                "relationships": [
                    {"source": "user:alice", "target": "host:ws-12", "relation": "uses_host"},
                    {"source": "session:logon-22", "target": "host:ws-12", "relation": "occurs_on"},
                    {"source": "host:ws-12", "target": "ip:185.220.101.45", "relation": "linked_to"},
                ],
            },
            summary="Follow-up investigation confirmed the user, host, and C2 chain.",
        )

    app.state.agent_loop.investigate = AsyncMock(side_effect=fake_follow_up_investigate)

    follow_up = client.post(
        "/api/chat",
        json={
            "session_id": initial_session,
            "message": "Pivot on the user, host, and session tied to the beaconing IP.",
        },
    )
    assert follow_up.status_code == 200
    follow_up_session = follow_up.json()["session_id"]

    investigate_kwargs = app.state.agent_loop.investigate.await_args.kwargs
    assert investigate_kwargs["case_id"] == case_id
    assert investigate_kwargs["metadata"]["agent_profile_id"] == "phishing_analyst"

    follow_up_chat = client.get(f"/agent/chat?session={follow_up_session}")
    assert follow_up_chat.status_code == 200

    chat_session = client.get(f"/api/chat/sessions/{follow_up_session}")
    assert chat_session.status_code == 200
    chat_payload = chat_session.json()
    assert chat_payload["case_id"] == case_id
    assert chat_payload["deterministic_decision"]["verdict"] == "MALICIOUS"
    assert chat_payload["root_cause_assessment"]["primary_root_cause"].startswith("alice executed the phishing payload")
    assert chat_payload["reasoning_state"]["hypotheses"][0]["id"] == "hyp-follow-up"
    assert "session:logon-22" in chat_payload["entity_state"]["entities"]

    investigations_page = client.get("/agent/investigations")
    assert investigations_page.status_code == 200
    assert "buildSessionReasoningTab" in investigations_page.text
    assert "/agent/chat?session=" in investigations_page.text
    assert "Missing Evidence / Next Pivots" in investigations_page.text

    sessions_payload = client.get("/api/agent/sessions")
    assert sessions_payload.status_code == 200
    sessions = sessions_payload.json()["sessions"]
    by_id = {item["session_id"]: item for item in sessions}
    assert initial_session in by_id
    assert follow_up_session in by_id
    assert by_id[follow_up_session]["deterministic_decision"]["score"] == 96
    assert by_id[follow_up_session]["agentic_explanation"]["root_cause_assessment"]["status"] == "supported"

    detail_payload = client.get(f"/api/agent/sessions/{follow_up_session}")
    assert detail_payload.status_code == 200
    assert detail_payload.json()["root_cause_assessment"]["summary"] == "Follow-up pivots tied the malicious infrastructure directly to alice on WS-12."

    case_page = client.get(f"/cases/{case_id}")
    assert case_page.status_code == 200
    assert case_id in case_page.text
    assert 'id="caseReasoningPanels"' in case_page.text

    case_reasoning = client.get(f"/api/cases/{case_id}/reasoning")
    assert case_reasoning.status_code == 200
    reasoning_payload = case_reasoning.json()
    assert reasoning_payload["latest_session_id"] == follow_up_session
    assert reasoning_payload["latest_workflow_id"] == "wf-phishing-followup"
    assert reasoning_payload["deterministic_decision"]["score"] == 96
    assert reasoning_payload["root_cause_assessment"]["primary_root_cause"].startswith("alice executed the phishing payload")
    assert len(reasoning_payload["workflow_sessions"]) == 2


def test_case_reasoning_route_prefers_root_cause_backed_session_when_multiple_workflows_exist(tmp_path):
    app = _build_isolated_app(tmp_path)
    client = TestClient(app)

    create_case = client.post(
        "/api/cases",
        json={"title": "Session selection case", "description": "Root-cause precedence", "severity": "medium"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["id"]

    root_cause_session = _seed_reasoning_session(
        app,
        case_id=case_id,
        goal="Investigate phishing-delivered payload",
        workflow_id="wf-root-cause",
        agent_profile_id="investigator",
        deterministic_decision={"score": 88, "severity": "high", "verdict": "MALICIOUS", "confidence": 0.88},
        root_cause_assessment={
            "primary_root_cause": "Phishing email delivered the payload.",
            "summary": "This workflow produced the authoritative root-cause assessment.",
            "status": "supported",
            "confidence": 0.82,
            "causal_chain": ["Email delivered", "User clicked link", "Payload executed"],
            "missing_evidence": [],
        },
        reasoning_state={
            "status": "supported",
            "hypotheses": [
                {
                    "id": "hyp-root",
                    "statement": "The phishing workflow explains the incident.",
                    "status": "supported",
                    "confidence": 0.82,
                    "supporting_evidence_refs": [],
                    "contradicting_evidence_refs": [],
                    "open_questions": [],
                }
            ],
        },
        entity_state={"entities": {"user:alice": {"id": "user:alice", "type": "user", "value": "alice", "label": "alice"}}},
        summary="Root cause workflow completed.",
    )

    newer_session = app.state.agent_store.create_session(goal="Investigate noisy follow-up alert", case_id=case_id)
    app.state.agent_store.update_session_metadata(
        newer_session,
        {
            "workflow_id": "wf-noise",
            "deterministic_decision": {"score": 12, "severity": "low", "verdict": "BENIGN", "confidence": 0.4},
            "reasoning_state": {
                "status": "collecting_evidence",
                "hypotheses": [
                    {
                        "id": "hyp-noise",
                        "statement": "The later activity may be benign noise.",
                        "status": "open",
                        "confidence": 0.41,
                        "supporting_evidence_refs": [],
                        "contradicting_evidence_refs": [],
                        "open_questions": ["Need more context on the alert source."],
                    }
                ],
            },
            "entity_state": {
                "entities": {
                    "host:ws-99": {"id": "host:ws-99", "type": "host", "value": "WS-99", "label": "WS-99"},
                }
            },
        },
    )
    app.state.agent_store.update_session_status(newer_session, "completed", "Later alert looks benign.")
    app.state.case_store.link_workflow(case_id, newer_session, "wf-noise")

    investigations_page = client.get("/agent/investigations")
    assert investigations_page.status_code == 200

    case_page = client.get(f"/cases/{case_id}")
    assert case_page.status_code == 200

    reasoning_response = client.get(f"/api/cases/{case_id}/reasoning")
    assert reasoning_response.status_code == 200
    payload = reasoning_response.json()
    assert payload["latest_session_id"] == root_cause_session
    assert payload["latest_workflow_id"] == "wf-root-cause"
    assert payload["deterministic_decision"]["verdict"] == "MALICIOUS"
    assert payload["root_cause_assessment"]["summary"] == "This workflow produced the authoritative root-cause assessment."
    assert payload["reasoning_state"]["hypotheses"][0]["id"] == "hyp-root"
