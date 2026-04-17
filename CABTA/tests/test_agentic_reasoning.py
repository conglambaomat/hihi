from unittest.mock import AsyncMock, patch

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.entity_resolver import EntityResolver
from src.agent.evidence_graph import EvidenceGraph
from src.agent.agent_state import AgentState
from src.agent.agent_store import AgentStore
from src.agent.hypothesis_manager import HypothesisManager
from src.agent.tool_registry import ToolRegistry
from src.case_intelligence.service import CaseIntelligenceService
from src.web.analysis_manager import AnalysisManager
from src.web.case_store import CaseStore
from src.web.routes.agent import _decorate_session_payload


def _make_agent_loop(tmp_path, case_store=None):
    db = tmp_path / "agentic_reasoning.db"
    return AgentLoop(
        config={
            "agent": {"max_steps": 4},
            "llm": {
                "provider": "ollama",
                "ollama_endpoint": "http://localhost:11434",
                "ollama_model": "llama3.1:8b",
                "groq_endpoint": "https://api.groq.com/openai/v1",
                "groq_model": "openai/gpt-oss-20b",
                "anthropic_model": "claude-sonnet-4-20250514",
                "gemini_endpoint": "https://generativelanguage.googleapis.com/v1beta/openai",
                "gemini_model": "gemini-2.5-flash",
            },
            "api_keys": {"anthropic": "", "groq": "", "gemini": ""},
        },
        tool_registry=ToolRegistry(),
        agent_store=AgentStore(db_path=str(db)),
        case_store=case_store,
    )


class TestHypothesisManager:
    def test_bootstrap_creates_required_fields(self):
        manager = HypothesisManager()

        reasoning_state = manager.bootstrap(
            "Investigate whether secure-payroll-check.com is a phishing domain.",
            "sess-123",
        )

        assert reasoning_state["session_id"] == "sess-123"
        assert reasoning_state["status"] == "collecting_evidence"
        assert len(reasoning_state["hypotheses"]) >= 2

        hypothesis = reasoning_state["hypotheses"][0]
        assert sorted(hypothesis.keys()) == sorted(
            [
                "id",
                "statement",
                "status",
                "confidence",
                "supporting_evidence_refs",
                "contradicting_evidence_refs",
                "open_questions",
                "created_at",
                "updated_at",
            ]
        )

    def test_revise_supports_malicious_hypothesis_and_tracks_evidence_refs(self):
        manager = HypothesisManager()
        reasoning_state = manager.bootstrap("Investigate 185.220.101.12", "sess-123")

        updated = manager.revise(
            reasoning_state,
            goal="Investigate 185.220.101.12",
            session_id="sess-123",
            tool_name="investigate_ioc",
            params={"ioc": "185.220.101.12"},
            result={"verdict": "MALICIOUS", "score": 91, "severity": "high"},
            finding_index=0,
            step_number=0,
        )

        primary = updated["hypotheses"][0]
        alternate = updated["hypotheses"][1]
        assert primary["status"] == "open" or primary["status"] == "supported"
        assert primary["confidence"] > 0.35
        assert primary["supporting_evidence_refs"][0]["tool_name"] == "investigate_ioc"
        assert alternate["contradicting_evidence_refs"][0]["stance"] == "supports"

    def test_revise_can_strengthen_benign_hypothesis(self):
        manager = HypothesisManager()
        reasoning_state = manager.bootstrap("Investigate 8.8.8.8", "sess-456")

        updated = manager.revise(
            reasoning_state,
            goal="Investigate 8.8.8.8",
            session_id="sess-456",
            tool_name="investigate_ioc",
            params={"ioc": "8.8.8.8"},
            result={"verdict": "CLEAN", "score": 5, "severity": "low"},
            finding_index=0,
            step_number=0,
        )

        primary = updated["hypotheses"][0]
        benign = updated["hypotheses"][1]
        assert primary["contradicting_evidence_refs"]
        assert benign["supporting_evidence_refs"]
        assert benign["confidence"] > 0.2

    def test_revise_treats_explicit_malicious_verdict_as_support_even_with_benign_words_in_nested_text(self):
        manager = HypothesisManager()
        reasoning_state = manager.bootstrap("Investigate 185.220.101.45", "sess-789")

        updated = manager.revise(
            reasoning_state,
            goal="Investigate 185.220.101.45",
            session_id="sess-789",
            tool_name="investigate_ioc",
            params={"ioc": "185.220.101.45"},
            result={
                "ioc": "185.220.101.45",
                "verdict": "MALICIOUS",
                "threat_score": 100,
                "llm_analysis": {
                    "analysis": "This IP is malicious, but confirm whether any legitimate traffic exists around it.",
                },
            },
            finding_index=0,
            step_number=0,
        )

        primary = updated["hypotheses"][0]
        assert updated["recent_evidence_refs"][-1]["stance"] == "supports"
        assert primary["status"] == "supported"
        assert primary["confidence"] >= 0.6


class TestEntityAndEvidenceState:
    def test_entity_resolver_normalizes_entities_and_relationships(self):
        resolver = EntityResolver()
        state = resolver.ingest_observation(
            None,
            session_id="sess-1",
            tool_name="search_logs",
            params={"query": "dest_ip=185.220.101.45"},
            result={
                "results": [
                    {
                        "user": "alice",
                        "host": "WS-12",
                        "dest_ip": "185.220.101.45",
                        "process_name": "powershell.exe",
                        "session_id": "LOGON-22",
                    }
                ]
            },
            step_number=2,
            evidence_ref={
                "tool_name": "search_logs",
                "step_number": 2,
                "finding_index": 0,
                "summary": "Observed alice on WS-12 connecting to 185.220.101.45 via powershell.exe.",
                "created_at": "2026-04-17T00:00:00+00:00",
            },
        )

        entities = state["entities"]
        assert "user:alice" in entities
        assert "host:ws-12" in entities
        assert any(item["type"] == "host" and item["value"] == "WS-12" for item in entities.values())
        assert any(rel["relation"] == "associated_with" for rel in state["relationships"])
        assert any(rel["relation"] == "uses_host" for rel in state["relationships"])

    def test_evidence_graph_tracks_supports_and_timeline(self):
        graph = EvidenceGraph()
        graph_state = graph.ingest_observation(
            None,
            session_id="sess-2",
            tool_name="investigate_ioc",
            step_number=1,
            evidence_ref={
                "tool_name": "investigate_ioc",
                "step_number": 1,
                "finding_index": 0,
                "summary": "The IOC was flagged as malicious.",
                "created_at": "2026-04-17T00:00:00+00:00",
            },
            entity_state={
                "entities": {
                    "ip:185.220.101.45": {"id": "ip:185.220.101.45", "type": "ip", "value": "185.220.101.45", "label": "185.220.101.45"},
                },
                "observations": [{"step_number": 1, "entity_ids": ["ip:185.220.101.45"]}],
            },
        )
        graph_state = graph.sync_reasoning(
            graph_state,
            session_id="sess-2",
            reasoning_state={
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "statement": "This is malicious infrastructure.",
                        "status": "supported",
                        "confidence": 0.8,
                        "supporting_evidence_refs": [
                            {
                                "tool_name": "investigate_ioc",
                                "step_number": 1,
                                "finding_index": 0,
                                "summary": "The IOC was flagged as malicious.",
                            }
                        ],
                        "contradicting_evidence_refs": [],
                    }
                ]
            },
            root_cause_assessment={
                "primary_root_cause": "Malicious infrastructure used for C2.",
                "summary": "The infrastructure is likely used for malicious command and control.",
                "supporting_evidence_refs": [
                    {
                        "tool_name": "investigate_ioc",
                        "step_number": 1,
                        "finding_index": 0,
                        "summary": "The IOC was flagged as malicious.",
                    }
                ],
                "assessed_at": "2026-04-17T00:00:01+00:00",
                "status": "supported",
                "confidence": 0.8,
            },
        )

        relations = {(edge["source"], edge["target"], edge["relation"]) for edge in graph_state["edges"]}
        assert any(relation == "supports" for _, _, relation in relations)
        assert any(relation == "derived_from" for _, _, relation in relations)
        assert any(event["type"] == "root_cause_assessment" for event in graph_state["timeline"])


class TestAgentLoopReasoning:
    @pytest.mark.asyncio
    async def test_chat_with_tools_uses_failover_provider_and_preserves_filtered_tool_list(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        loop.provider = "gemini"
        loop.auto_failover = True
        loop.fallback_providers = ["groq"]
        loop.gemini_key = "dummy"
        loop.groq_key = "dummy"

        loop._gemini_chat = AsyncMock(return_value=None)
        loop._groq_chat = AsyncMock(return_value='{"action":"final_answer","answer":"done","verdict":"MALICIOUS"}')

        filtered_tools = [{"function": {"name": "investigate_ioc"}}]
        raw = await loop._chat_with_tools(
            [{"role": "user", "content": "Investigate IOC"}],
            tools_json=filtered_tools,
        )

        assert raw == '{"action":"final_answer","answer":"done","verdict":"MALICIOUS"}'
        loop._gemini_chat.assert_awaited_once()
        loop._groq_chat.assert_awaited_once()
        assert loop._groq_chat.await_args.args[1] == filtered_tools

    def test_simple_chat_enrichment_prefers_single_high_value_pivot(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        loop.tools.register_mcp_tools(
            "network-analysis",
            [
                {
                    "name": "geoip_lookup",
                    "description": "GeoIP lookup",
                    "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}},
                }
            ],
        )

        calls = loop._get_enrichment_mcp_tools(
            "investigate_ioc",
            {"ioc": "185.220.101.45"},
            "Investigate whether 185.220.101.45 is malicious infrastructure.",
        )

        assert calls == [("network-analysis.geoip_lookup", {"ip": "185.220.101.45"})]

    def test_follow_up_lookup_question_is_treated_as_simple_chat(self, tmp_path):
        loop = _make_agent_loop(tmp_path)

        assert loop._is_simple_chat_goal(
            "What organization and host name are tied to this IP?",
            "investigate_ioc",
        ) is True

    def test_simple_chat_short_circuits_to_correlation_and_final_answer(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        session_id = loop.store.create_session(
            goal="Is 185.220.101.45 malicious?",
            metadata={"chat_mode": True, "response_style": "conversational"},
        )
        state = AgentState(
            session_id=session_id,
            goal="Is 185.220.101.45 malicious?",
            max_steps=4,
        )

        state.add_finding(
            {
                "type": "tool_result",
                "tool": "investigate_ioc",
                "params": {"ioc": "185.220.101.45"},
                "result": {"ioc": "185.220.101.45", "verdict": "MALICIOUS", "threat_score": 100},
            }
        )
        loop._refresh_reasoning_outputs(
            session_id,
            state,
            tool_name="investigate_ioc",
            params={"ioc": "185.220.101.45"},
            result={"ioc": "185.220.101.45", "verdict": "MALICIOUS", "threat_score": 100},
        )
        state.step_count += 1

        state.add_finding(
            {
                "type": "tool_result",
                "tool": "network-analysis.geoip_lookup",
                "params": {"ip": "185.220.101.45"},
                "result": {
                    "result": {
                        "ip": "185.220.101.45",
                        "country": "Germany",
                        "organization": "ForPrivacyNET",
                        "reverse_dns": "tor-exit-45.for-privacy.net",
                    }
                },
            }
        )
        loop._refresh_reasoning_outputs(
            session_id,
            state,
            tool_name="network-analysis.geoip_lookup",
            params={"ip": "185.220.101.45"},
            result={
                "result": {
                    "ip": "185.220.101.45",
                    "country": "Germany",
                    "organization": "ForPrivacyNET",
                    "reverse_dns": "tor-exit-45.for-privacy.net",
                }
            },
        )
        state.step_count += 1

        async def correlate_findings(**kwargs):
            return {
                "severity": "critical",
                "statistics": {"unique_iocs": 1},
            }

        loop.tools.register_local_tool(
            name="correlate_findings",
            description="Correlate findings",
            parameters={"properties": {"findings": {"type": "array"}}},
            category="analysis",
            executor=correlate_findings,
        )

        decision = loop._chat_short_circuit_decision(state)
        assert decision is not None
        assert decision["action"] == "use_tool"
        assert decision["tool"] == "correlate_findings"

        state.add_finding(
            {
                "type": "tool_result",
                "tool": "correlate_findings",
                "params": {"findings": state.findings[-2:]},
                "result": {
                    "severity": "critical",
                    "statistics": {"unique_iocs": 1},
                },
            }
        )
        loop._refresh_reasoning_outputs(
            session_id,
            state,
            tool_name="correlate_findings",
            params={"findings": state.findings[-2:]},
            result={"severity": "critical", "statistics": {"unique_iocs": 1}},
        )

        decision = loop._chat_short_circuit_decision(state)
        assert decision is not None
        assert decision["action"] == "final_answer"
        assert decision["verdict"] == "MALICIOUS"
        assert "MALICIOUS" in decision["answer"]

    def test_chat_findings_block_uses_compact_evidence_summaries(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        session_id = loop.store.create_session(
            goal="Is 185.220.101.45 malicious?",
            metadata={"chat_mode": True},
        )
        state = AgentState(session_id=session_id, goal="Is 185.220.101.45 malicious?")
        state.add_finding(
            {
                "type": "tool_result",
                "tool": "investigate_ioc",
                "params": {"ioc": "185.220.101.45"},
                "result": {
                    "ioc": "185.220.101.45",
                    "verdict": "MALICIOUS",
                    "threat_score": 100,
                    "sources": {"virustotal": {"detections": "18/94"}},
                    "raw_blob": "X" * 2000,
                },
            }
        )

        findings_block = loop._build_findings_block(state)

        assert "classified as MALICIOUS" in findings_block
        assert "raw_blob" not in findings_block
        assert len(findings_block) < 400

    def test_fallback_answer_can_answer_org_and_hostname_question_from_evidence(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        session_id = loop.store.create_session(
            goal="What organization and host name are tied to this IP?",
            metadata={"chat_mode": True, "response_style": "conversational"},
        )
        state = AgentState(
            session_id=session_id,
            goal="What organization and host name are tied to this IP?",
        )
        state.reasoning_state = {"goal_focus": "185.220.101.45"}
        state.findings = [
            {
                "type": "tool_result",
                "tool": "network-analysis.geoip_lookup",
                "result": {
                    "result": {
                        "ip": "185.220.101.45",
                        "organization": "ForPrivacyNET",
                        "reverse_dns": "tor-exit-45.for-privacy.net",
                    }
                },
            }
        ]

        answer = loop._build_fallback_answer(
            state,
            {"kind": "verdict", "label": "MALICIOUS", "source": "investigate_ioc"},
        )

        assert "ForPrivacyNET" in answer
        assert "tor-exit-45.for-privacy.net" in answer

    @pytest.mark.asyncio
    async def test_run_loop_persists_reasoning_state_and_split_outputs(self, tmp_path):
        loop = _make_agent_loop(tmp_path)

        async def investigate_ioc(**kwargs):
            return {
                "ioc": kwargs["ioc"],
                "verdict": "MALICIOUS",
                "score": 93,
                "severity": "high",
                "confidence": 0.91,
                "policy_flags": ["needs_review"],
            }

        loop.tools.register_local_tool(
            name="investigate_ioc",
            description="Investigate IOC",
            parameters={"properties": {"ioc": {"type": "string"}}},
            category="analysis",
            executor=investigate_ioc,
        )

        session_id = loop.store.create_session(goal="Investigate 185.220.101.12")
        state = AgentState(session_id=session_id, goal="Investigate 185.220.101.12", max_steps=3)
        loop._active_sessions[session_id] = state
        loop._approval_events[session_id] = None

        with patch.object(
            loop,
            "_think",
            new_callable=AsyncMock,
            side_effect=[
                {
                    "action": "use_tool",
                    "tool": "investigate_ioc",
                    "params": {"ioc": "185.220.101.12"},
                    "reasoning": "Need evidence first.",
                },
                {
                    "action": "final_answer",
                    "answer": "The indicator looks malicious based on the available evidence.",
                    "verdict": "CLEAN",
                    "reasoning": "The narrative answer should not overwrite deterministic verdict ownership.",
                },
            ],
        ), patch.object(loop, "_generate_summary", new_callable=AsyncMock, return_value="done"):
            await loop._run_loop(session_id)

        session = loop.store.get_session(session_id)
        assert session is not None

        metadata = session["metadata"]
        assert metadata["deterministic_decision"]["verdict"] == "MALICIOUS"
        assert metadata["deterministic_decision"]["score"] == 93
        assert metadata["agentic_explanation"]["root_cause_assessment"]["summary"]
        assert metadata["reasoning_state"]["hypotheses"][0]["supporting_evidence_refs"]
        assert metadata["entity_state"]["entities"]
        assert metadata["evidence_state"]["timeline"]
        assert metadata["deterministic_decision_output"]["verdict"] == "MALICIOUS"
        assert metadata["agentic_explanation_output"]["root_cause_assessment"]["summary"]

        final_finding = [item for item in session["findings"] if item.get("type") == "final_answer"][-1]
        assert final_finding["verdict"] == "CLEAN"
        assert final_finding["verdict_authority"] == "deterministic_core"
        assert final_finding["deterministic_decision"]["verdict"] == "MALICIOUS"
        assert final_finding["agentic_explanation"]["root_cause_assessment"]["supporting_evidence_refs"]
        assert final_finding["entity_state"]["entities"]
        assert final_finding["evidence_state"]["timeline"]

    @pytest.mark.asyncio
    async def test_completed_case_session_mirrors_root_cause_into_case_events_and_case_intelligence(self, tmp_path):
        analysis_manager = AnalysisManager(db_path=str(tmp_path / "jobs.db"))
        case_store = CaseStore(db_path=str(tmp_path / "cases.db"))
        loop = _make_agent_loop(tmp_path, case_store=case_store)
        intelligence = CaseIntelligenceService(
            analysis_manager=analysis_manager,
            agent_store=loop.store,
            case_store=case_store,
        )

        async def search_logs(**kwargs):
            return {
                "results_count": 1,
                "results": [
                    {
                        "user": "alice",
                        "host": "WS-12",
                        "dest_ip": "185.220.101.45",
                        "session_id": "LOGON-22",
                        "process_name": "powershell.exe",
                    }
                ],
                "severity": "high",
            }

        loop.tools.register_local_tool(
            name="search_logs",
            description="Search logs",
            parameters={"properties": {"query": {"type": "string"}}},
            category="analysis",
            executor=search_logs,
        )

        case_id = case_store.create_case("Lead investigator test")
        session_id = loop.store.create_session(goal="Investigate suspicious session on WS-12", case_id=case_id)
        state = AgentState(session_id=session_id, goal="Investigate suspicious session on WS-12", max_steps=3)
        loop._active_sessions[session_id] = state
        loop._approval_events[session_id] = None

        with patch.object(
            loop,
            "_think",
            new_callable=AsyncMock,
            side_effect=[
                {
                    "action": "use_tool",
                    "tool": "search_logs",
                    "params": {"query": "dest_ip=185.220.101.45"},
                    "reasoning": "Trace the suspicious IP through user and host logs.",
                },
                {
                    "action": "final_answer",
                    "answer": "The evidence points to alice on WS-12 initiating the suspicious activity.",
                    "verdict": "UNKNOWN",
                    "reasoning": "Root cause is probably a user-initiated phishing execution chain.",
                },
            ],
        ), patch.object(loop, "_generate_summary", new_callable=AsyncMock, return_value="done"):
            await loop._run_loop(session_id)

        case = case_store.get_case(case_id)
        assert case is not None
        agentic_events = [event for event in case["events"] if event["event_type"] == "agentic_reasoning_checkpoint"]
        assert agentic_events
        payload = agentic_events[-1]["payload"]
        assert payload["root_cause_assessment"]["summary"]
        assert payload["entity_summary"]["entity_count"] >= 3
        assert payload["evidence_timeline"]

        graph = intelligence.build_graph(case_id)
        timeline = intelligence.build_timeline(case_id)
        assert graph is not None
        assert any(node["type"] == "root_cause" for node in graph["nodes"])
        assert any(node["type"] == "hypothesis" for node in graph["nodes"])
        assert any(edge["relation"] in {"supports", "linked_to", "associated_with", "uses_host"} for edge in graph["edges"])
        assert timeline is not None
        assert any(event["type"] == "agentic_reasoning_checkpoint" for event in timeline["events"])
        assert any(event["type"] == "workflow_root_cause_assessed" or event["type"] == "root_cause_assessment" for event in timeline["events"])

    def test_decorate_session_payload_promotes_reasoning_metadata(self):
        payload = _decorate_session_payload(
            {
                "id": "sess-789",
                "metadata": {
                    "reasoning_state": {"status": "collecting_evidence"},
                    "entity_state": {"entities": {}},
                    "evidence_state": {"timeline": []},
                    "deterministic_decision": {"verdict": "MALICIOUS"},
                    "deterministic_decision_output": {"verdict": "MALICIOUS"},
                    "agentic_explanation": {"root_cause_assessment": {"summary": "Likely phishing."}},
                    "agentic_explanation_output": {"root_cause_assessment": {"summary": "Likely phishing."}},
                    "root_cause_assessment": {"summary": "Likely phishing."},
                },
            }
        )

        assert payload["session_id"] == "sess-789"
        assert payload["reasoning_state"]["status"] == "collecting_evidence"
        assert payload["entity_state"]["entities"] == {}
        assert payload["evidence_state"]["timeline"] == []
        assert payload["deterministic_decision"]["verdict"] == "MALICIOUS"
        assert payload["deterministic_decision_output"]["verdict"] == "MALICIOUS"
        assert payload["agentic_explanation"]["root_cause_assessment"]["summary"] == "Likely phishing."
        assert payload["agentic_explanation_output"]["root_cause_assessment"]["summary"] == "Likely phishing."
        assert payload["root_cause_assessment"]["summary"] == "Likely phishing."

    def test_case_reasoning_summary_keeps_root_cause_and_decision_from_same_session(self, tmp_path):
        analysis_manager = AnalysisManager(db_path=str(tmp_path / "jobs.db"))
        case_store = CaseStore(db_path=str(tmp_path / "cases.db"))
        loop = _make_agent_loop(tmp_path, case_store=case_store)
        intelligence = CaseIntelligenceService(
            analysis_manager=analysis_manager,
            agent_store=loop.store,
            case_store=case_store,
        )

        case_id = case_store.create_case("Reasoning consistency case")

        session_a = loop.store.create_session(goal="Investigate phishing chain", case_id=case_id)
        loop.store.update_session_metadata(
            session_a,
            {
                "deterministic_decision": {"verdict": "MALICIOUS", "score": 91, "severity": "high"},
                "agentic_explanation": {
                    "root_cause_assessment": {
                        "primary_root_cause": "Phishing email delivered the payload.",
                        "summary": "Phishing delivery is the strongest explanation.",
                        "status": "supported",
                        "confidence": 0.84,
                    },
                    "reasoning_status": "supported",
                },
                "root_cause_assessment": {
                    "primary_root_cause": "Phishing email delivered the payload.",
                    "summary": "Phishing delivery is the strongest explanation.",
                    "status": "supported",
                    "confidence": 0.84,
                },
                "reasoning_state": {
                    "status": "supported",
                    "hypotheses": [
                        {
                            "id": "hyp-a",
                            "statement": "The payload was delivered through phishing.",
                            "status": "supported",
                            "confidence": 0.84,
                            "supporting_evidence_refs": [],
                            "contradicting_evidence_refs": [],
                            "open_questions": [],
                        }
                    ],
                },
                "entity_state": {
                    "entities": {
                        "user:alice": {"id": "user:alice", "type": "user", "value": "alice", "label": "alice"},
                    }
                },
            },
        )
        case_store.link_workflow(case_id, session_a, "wf-phishing")
        case_store.add_event(
            case_id,
            event_type="root_cause_assessment",
            title="Root cause assessment updated",
            payload={
                "session_id": session_a,
                "root_cause_assessment": {
                    "primary_root_cause": "Phishing email delivered the payload.",
                    "summary": "Phishing delivery is the strongest explanation.",
                    "status": "supported",
                    "confidence": 0.84,
                },
                "deterministic_decision": {"verdict": "MALICIOUS", "score": 91, "severity": "high"},
            },
        )

        session_b = loop.store.create_session(goal="Investigate follow-up noise", case_id=case_id)
        loop.store.update_session_metadata(
            session_b,
            {
                "deterministic_decision": {"verdict": "BENIGN", "score": 8, "severity": "low"},
                "reasoning_state": {
                    "status": "collecting_evidence",
                    "hypotheses": [
                        {
                            "id": "hyp-b",
                            "statement": "The later activity is benign noise.",
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
                        "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12", "label": "WS-12"},
                    }
                },
            },
        )
        case_store.link_workflow(case_id, session_b, "wf-noise")

        summary = intelligence.build_reasoning_summary(case_id)

        assert summary is not None
        assert summary["latest_session_id"] == session_a
        assert summary["latest_workflow_id"] == "wf-phishing"
        assert summary["deterministic_decision"]["verdict"] == "MALICIOUS"
        assert summary["root_cause_assessment"]["primary_root_cause"] == "Phishing email delivered the payload."
        assert summary["reasoning_state"]["hypotheses"][0]["id"] == "hyp-a"
        assert "user:alice" in summary["entity_state"]["entities"]
