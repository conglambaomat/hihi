from unittest.mock import AsyncMock, patch

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.entity_resolver import EntityResolver
from src.agent.evidence_graph import EvidenceGraph
from src.agent.investigation_planner import InvestigationPlanner
from src.agent.agent_state import AgentState
from src.agent.agent_store import AgentStore
from src.agent.hypothesis_manager import HypothesisManager
from src.agent.observation_normalizer import ObservationNormalizer
from src.agent.root_cause_engine import RootCauseEngine
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
        assert "topics" in hypothesis
        assert "evidence_score" in hypothesis
        assert "contradiction_score" in hypothesis
        assert "priority" in hypothesis
        assert "last_updated_at" in hypothesis

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
        assert alternate["contradicting_evidence_refs"][0]["stance"] == "contradicts"
        assert primary["evidence_score"] > 0

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
        assert primary["status"] in {"open", "supported"}
        assert primary["confidence"] > 0.35
        assert primary["evidence_score"] > 0.0

    def test_revise_search_logs_without_matches_stays_neutral(self):
        manager = HypothesisManager()
        reasoning_state = manager.bootstrap("Check 8.8.8.8 and tell me if it looks suspicious.", "sess-790")

        updated = manager.revise(
            reasoning_state,
            goal="Check 8.8.8.8 and tell me if it looks suspicious.",
            session_id="sess-790",
            tool_name="search_logs",
            params={"query": "Investigate 8.8.8.8"},
            result={
                "status": "executed",
                "results_count": 0,
                "results": [],
                "suspicious_indicators": [],
                "suspicious_files": [],
                "suspicious_executables": [],
                "message": "Seeded demo log hunt completed without matches.",
            },
            finding_index=0,
            step_number=0,
        )

        primary = updated["hypotheses"][0]
        alternate = updated["hypotheses"][1]
        assert updated["recent_evidence_refs"][-1]["stance"] == "neutral"
        assert primary["supporting_evidence_refs"] == []
        assert alternate["contradicting_evidence_refs"] == []
        assert primary["confidence"] == pytest.approx(0.34)

    def test_revise_close_competing_hypotheses_stays_collecting(self):
        manager = HypothesisManager()
        state = manager.bootstrap("Investigate suspicious user login sequence", "sess-791")

        state = manager.revise(
            state,
            goal="Investigate suspicious user login sequence",
            session_id="sess-791",
            tool_name="search_logs",
            params={"query": "user=alice"},
            result={
                "status": "executed",
                "results_count": 1,
                "results": [{"user": "alice", "host": "WS-12", "source_ip": "10.0.0.5", "action": "login"}],
            },
            finding_index=0,
            step_number=0,
            observations=[
                {
                    "observation_id": "obs:sess-791:0:0",
                    "tool_name": "search_logs",
                    "observation_type": "auth_event",
                    "timestamp": "2026-04-19T00:00:00+00:00",
                    "summary": "Auth telemetry: user=alice, host=WS-12, source_ip=10.0.0.5",
                    "quality": 0.62,
                    "source_kind": "log_row",
                    "source_paths": ["result.results[0]"],
                    "entities": [
                        {"type": "user", "value": "alice", "label": "alice", "source_path": "result.results[0].user", "confidence": 0.9},
                        {"type": "host", "value": "WS-12", "label": "WS-12", "source_path": "result.results[0].host", "confidence": 0.9},
                    ],
                    "facts": {"user": "alice", "host": "WS-12", "source_ip": "10.0.0.5"},
                    "raw_ref": {},
                }
            ],
        )

        assert state["status"] == "insufficient_evidence"
        assert state["missing_evidence"]
        assert state["hypotheses"][0]["confidence"] - state["hypotheses"][1]["confidence"] < 0.25

    def test_bootstrap_seeds_missing_evidence_from_investigation_plan(self):
        manager = HypothesisManager()

        state = manager.bootstrap(
            "Investigate suspicious login from 185.220.101.45",
            "sess-plan",
            investigation_plan={
                "lane": "log_identity",
                "initial_hypotheses": ["Credential misuse is likely."],
                "evidence_gaps": [
                    "Need explicit user, host, session, and process linkage.",
                    "Need stronger attribution between auth evidence and downstream process or network activity.",
                ],
            },
        )

        assert state["investigation_lane"] == "log_identity"
        assert any("explicit user, host, session, and process linkage" in item for item in state["missing_evidence"])

    def test_revise_prefers_typed_topic_alignment_for_email_hypothesis_support(self):
        manager = HypothesisManager()
        state = manager.bootstrap(
            "Investigate suspicious finance email",
            "sess-typed-email",
            investigation_plan={
                "lane": "email",
                "initial_hypotheses": ["Initial access likely occurred through phishing or malicious email delivery."],
                "evidence_gaps": ["Need delivery evidence linking sender, recipient, and any attachment or URL."],
            },
        )

        updated = manager.revise(
            state,
            goal="Investigate suspicious finance email",
            session_id="sess-typed-email",
            tool_name="analyze_email",
            params={"message_id": "msg-1"},
            result={},
            finding_index=0,
            step_number=0,
            observations=[
                {
                    "observation_id": "obs:sess-typed-email:0:0",
                    "tool_name": "analyze_email",
                    "observation_type": "email_delivery",
                    "summary": "Email delivery evidence shows spoofed sender and malicious attachment delivery.",
                    "quality": 0.83,
                    "source_kind": "email_headers",
                    "source_paths": ["result.headers"],
                    "typed_fact": {
                        "type": "email_delivery",
                        "family": "email",
                        "quality": 0.83,
                    },
                    "facts": {
                        "verdict": "MALICIOUS",
                        "severity": "high",
                        "sender": "payroll@secure-payroll-check.com",
                        "recipient": "finance@corp.local",
                    },
                    "entities": [
                        {"type": "sender", "value": "payroll@secure-payroll-check.com"},
                        {"type": "recipient", "value": "finance@corp.local"},
                    ],
                }
            ],
        )

        primary = updated["hypotheses"][0]
        assert primary["supporting_evidence_refs"]
        assert primary["supporting_evidence_refs"][0]["causal_relevance"] >= 0.8
        assert primary["confidence"] > 0.34


    def test_revise_prefers_typed_topic_alignment_for_log_identity_hypothesis_support(self):
        manager = HypothesisManager()
        state = manager.bootstrap(
            "Investigate suspicious login sequence",
            "sess-typed-auth",
            investigation_plan={
                "lane": "log_identity",
                "initial_hypotheses": ["Credential misuse or session abuse is the strongest specialized hypothesis."],
                "evidence_gaps": ["Need explicit user, host, session, and process linkage."],
            },
        )

        updated = manager.revise(
            state,
            goal="Investigate suspicious login sequence",
            session_id="sess-typed-auth",
            tool_name="search_logs",
            params={"query": "user=alice"},
            result={},
            finding_index=0,
            step_number=0,
            observations=[
                {
                    "observation_id": "obs:sess-typed-auth:0:0",
                    "tool_name": "search_logs",
                    "observation_type": "auth_event",
                    "summary": "Authentication event shows suspicious session reuse for alice.",
                    "quality": 0.79,
                    "source_kind": "log_row",
                    "source_paths": ["result.results[0]"],
                    "typed_fact": {
                        "type": "auth_event",
                        "family": "identity",
                        "quality": 0.79,
                    },
                    "facts": {
                        "user": "alice",
                        "session_id": "S-1",
                        "verdict": "SUSPICIOUS",
                        "severity": "high",
                    },
                    "entities": [
                        {"type": "user", "value": "alice"},
                        {"type": "session", "value": "S-1"},
                    ],
                }
            ],
        )

        primary = updated["hypotheses"][0]
        assert primary["supporting_evidence_refs"]
        assert primary["supporting_evidence_refs"][0]["causal_relevance"] >= 0.9
        assert primary["confidence"] > 0.34


    def test_revise_does_not_overweight_tag_only_overlap_without_typed_alignment(self):
        manager = HypothesisManager()
        state = manager.bootstrap(
            "Investigate whether this domain is suspicious",
            "sess-tag-fallback",
            investigation_plan={
                "lane": "ioc",
                "initial_hypotheses": ["The observed activity is likely tied to phishing delivery infrastructure."],
                "evidence_gaps": ["Need deterministic enrichment or corroboration that ties the IOC to malicious or benign activity."],
            },
        )

        updated = manager.revise(
            state,
            goal="Investigate whether this domain is suspicious",
            session_id="sess-tag-fallback",
            tool_name="investigate_ioc",
            params={"ioc": "example-bad-domain.test"},
            result={},
            finding_index=0,
            step_number=0,
            observations=[
                {
                    "observation_id": "obs:sess-tag-fallback:0:0",
                    "tool_name": "investigate_ioc",
                    "observation_type": "ioc_enrichment",
                    "summary": "IOC enrichment references phishing in free-text but provides generic network enrichment.",
                    "quality": 0.55,
                    "source_kind": "ioc_result",
                    "source_paths": ["result"],
                    "typed_fact": {
                        "type": "ioc_enrichment",
                        "family": "network",
                        "quality": 0.55,
                    },
                    "facts": {
                        "verdict": "SUSPICIOUS",
                        "severity": "medium",
                    },
                    "entities": [
                        {"type": "domain", "value": "example-bad-domain.test"},
                    ],
                }
            ],
        )

        primary = updated["hypotheses"][0]
        assert primary["supporting_evidence_refs"]
        assert primary["supporting_evidence_refs"][0]["confidence"] < 0.5


    def test_revise_uses_explicit_relationships_and_plan_gaps_for_evidence_aware_state(self):
        manager = HypothesisManager()
        plan = {
            "lane": "log_identity",
            "initial_hypotheses": ["Credential misuse or session abuse is the strongest specialized hypothesis."],
            "evidence_gaps": ["Need explicit user, host, session, and process linkage."],
        }
        state = manager.bootstrap(
            "Investigate suspicious login sequence for alice on WS-12",
            "sess-rel",
            investigation_plan=plan,
        )

        state = manager.revise(
            state,
            goal="Investigate suspicious login sequence for alice on WS-12",
            session_id="sess-rel",
            tool_name="search_logs",
            params={"query": "user=alice"},
            result={},
            finding_index=0,
            step_number=1,
            investigation_plan=plan,
            entity_state={
                "entities": {
                    "user:alice": {"id": "user:alice", "type": "user", "value": "alice"},
                    "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12"},
                    "session:logon-22": {"id": "session:logon-22", "type": "session", "value": "LOGON-22"},
                    "ip:185.220.101.45": {"id": "ip:185.220.101.45", "type": "ip", "value": "185.220.101.45"},
                },
                "relationships": [
                    {
                        "source": "session:logon-22",
                        "target": "user:alice",
                        "relation": "belongs_to",
                        "relation_strength": "explicit",
                    },
                    {
                        "source": "session:logon-22",
                        "target": "ip:185.220.101.45",
                        "relation": "authenticated_from",
                        "relation_strength": "explicit",
                    },
                ],
            },
            evidence_state={
                "timeline": [
                    {"type": "observation", "timestamp": "2026-04-19T00:00:00+00:00"},
                    {"type": "observation", "timestamp": "2026-04-19T00:01:00+00:00"},
                ]
            },
            observations=[
                {
                    "observation_id": "obs-auth-explicit",
                    "observation_type": "auth_event",
                    "summary": "Auth telemetry tied alice to session LOGON-22 from 185.220.101.45 on WS-12.",
                    "quality": 0.55,
                    "source_kind": "log_row",
                    "source_paths": ["result.results[0]"],
                    "entities": [
                        {"type": "user", "value": "alice", "label": "alice", "source_path": "result.results[0].user", "confidence": 0.9},
                        {"type": "host", "value": "WS-12", "label": "WS-12", "source_path": "result.results[0].host", "confidence": 0.9},
                        {"type": "session", "value": "LOGON-22", "label": "LOGON-22", "source_path": "result.results[0].session_id", "confidence": 0.9},
                        {"type": "ip", "value": "185.220.101.45", "label": "185.220.101.45", "source_path": "result.results[0].source_ip", "confidence": 0.95},
                    ],
                    "facts": {
                        "user": "alice",
                        "host": "WS-12",
                        "session_id": "LOGON-22",
                        "source_ip": "185.220.101.45",
                        "results_count": 1,
                    },
                }
            ],
        )

        assert state["recent_evidence_refs"][-1]["stance"] == "supports"
        assert state["recent_evidence_refs"][-1]["confidence"] > 0.35
        assert not any("Need at least one explicit relationship rather than co-observation alone." == item for item in state["missing_evidence"])

    def test_build_agentic_explanation_prioritizes_top_evidence_gap_pivot(self):
        manager = HypothesisManager()
        explanation = manager.build_agentic_explanation(
            {
                "session_id": "sess-expl",
                "status": "collecting_evidence",
                "goal_focus": "alice",
                "investigation_lane": "email",
                "missing_evidence": [
                    "Need delivery evidence linking sender, recipient, and any attachment or URL.",
                    "Need downstream host or user execution evidence before concluding impact.",
                ],
                "open_questions": ["Was the delivered email followed by user execution or host activity?"],
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "statement": "Initial access likely occurred through phishing or malicious email delivery.",
                        "status": "open",
                        "confidence": 0.52,
                        "topics": ["email", "email_delivery", "phishing"],
                        "supporting_evidence_refs": [],
                        "contradicting_evidence_refs": [],
                        "open_questions": [],
                        "evidence_score": 0.14,
                        "contradiction_score": 0.0,
                        "priority": 0.66,
                    }
                ],
            },
            goal="Investigate suspicious email delivery",
            deterministic_decision={"verdict": "SUSPICIOUS"},
            entity_state={
                "entities": {},
                "relationships": [
                    {"relation": "received_from", "relation_strength": "explicit"},
                    {"relation": "received_attachment", "relation_strength": "inferred"},
                ],
            },
        )

        pivots = explanation["recommended_next_pivots"]
        assert pivots
        assert pivots[0].startswith("Reduce the top evidence gap first:")
        assert any("sender-recipient delivery evidence" in item for item in pivots)
        assert any("delivered attachment was opened" in item for item in pivots)


class TestObservationPlannerAndRootCause:
    def test_investigation_planner_builds_log_identity_plan(self):
        planner = InvestigationPlanner()

        plan = planner.build_plan(
            "Pivot across login telemetry for user alice from IP 185.220.101.45 and confirm the session root cause."
        )

        assert plan["lane"] == "log_identity"
        assert "session" in plan["primary_entities"]
        assert plan["lead_profile"] == "investigator"
        assert "185.220.101.45" in plan["observable_summary"]
        assert plan["incident_type"] == "identity_or_session_activity"
        assert any("evidence gap" in item.lower() for item in plan["first_pivots"])
        assert any("user, host, session, and process linkage" in item for item in plan["evidence_gaps"])
        assert any("highest-priority evidence gap" in item for item in plan["stopping_conditions"])
        assert any("top evidence gap remains unresolved" in item for item in plan["escalation_conditions"])

    def test_investigation_planner_builds_email_plan_with_observable_summary_and_gaps(self):
        planner = InvestigationPlanner()

        plan = planner.build_plan(
            "Investigate phishing email from attacker@example.com delivering invoice.zip via example.com"
        )

        assert plan["lane"] == "email"
        assert plan["incident_type"] == "phishing_or_malicious_email"
        assert "attacker@example.com" in plan["observable_summary"]
        assert "example.com" in plan["observable_summary"]
        assert any("delivery evidence" in item.lower() for item in plan["evidence_gaps"])
        assert any("validate the strongest observable first" in item.lower() for item in plan["first_pivots"])

    def test_observation_normalizer_typed_log_rows(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-obs",
            tool_name="search_logs",
            params={"query": "user=alice"},
            result={
                "status": "executed",
                "results_count": 1,
                "results": [
                    {
                        "user": "alice",
                        "host": "WS-12",
                        "source_ip": "185.220.101.45",
                        "session_id": "LOGON-22",
                        "action": "login",
                    }
                ],
            },
            step_number=2,
        )

        typed = [item for item in payload["observations"] if item["observation_type"] == "auth_event"]
        assert typed
        assert payload["evidence_quality_summary"]["observation_count"] >= 1
        assert payload["evidence_quality_summary"]["fact_families"]["log"] >= 1
        assert any(entity["type"] == "session" for entity in typed[0]["entities"])
        assert typed[0]["schema_version"] == "typed-observation/v1"
        assert typed[0]["fact_family"] == "log"
        assert typed[0]["extraction_method"] == "normalizer"
        assert typed[0]["produced_at"]

    def test_observation_normalizer_keeps_correlation_as_compatibility_fallback_for_unknown_payloads(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-unknown",
            tool_name="custom_tool",
            params={"query": "opaque"},
            result="opaque unstructured payload",
            step_number=1,
        )

        assert payload["observations"]
        assert payload["observations"][0]["observation_type"] == "correlation_observation"
        assert payload["observations"][0]["fact_family"] == "correlation"


    def test_observation_normalizer_infers_typed_network_event_for_correlate_findings_payload(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-corr",
            tool_name="correlate_findings",
            params={},
            result={
                "result": {
                    "domain": "secure-payroll-check.com",
                    "dest_ip": "185.220.101.45",
                    "severity": "high",
                }
            },
            step_number=2,
        )

        assert payload["observations"]
        assert payload["observations"][0]["observation_type"] == "network_event"
        assert payload["observations"][0]["fact_family"] == "network"


    def test_observation_normalizer_infers_typed_file_execution_for_search_logs_aggregate_summary(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-log-agg",
            tool_name="search_logs",
            params={"query": "host=WS-12"},
            result={
                "status": "executed",
                "results_count": 0,
                "results": [],
                "suspicious_files": ["invoice.exe"],
                "suspicious_executables": ["powershell.exe"],
            },
            step_number=3,
        )

        aggregate = payload["observations"][-1]
        assert aggregate["observation_type"] == "file_execution"
        assert aggregate["fact_family"] == "file"


    def test_observation_normalizer_exposes_fact_family_schema_summary(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-schema-summary",
            tool_name="investigate_ioc",
            params={"ioc": "185.220.101.45"},
            result={
                "ioc": "185.220.101.45",
                "verdict": "MALICIOUS",
                "threat_score": 98,
                "severity": "high",
            },
            step_number=1,
        )

        assert "fact_family_schemas" in payload
        assert payload["fact_family_schemas"]["ioc"]["version"] == "fact-family/ioc/v1"
        assert "verdict" in payload["fact_family_schemas"]["ioc"]["canonical_fields"]
        assert "source_paths" in payload["fact_family_schemas"]["ioc"]["required_provenance"]

    def test_observation_normalizer_embeds_fact_family_schema_in_typed_fact_and_accepted_delta(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-schema-envelope",
            tool_name="analyze_email",
            params={"message_id": "msg-22"},
            result={
                "sender": "attacker@example.com",
                "recipient": "alice@corp.local",
                "attachment": "invoice.zip",
                "severity": "high",
                "verdict": "MALICIOUS",
                "threat_score": 91,
            },
            step_number=4,
        )

        observation = payload["observations"][0]
        assert observation["typed_fact"]["schema"]["version"] == "fact-family/email/v1"
        assert "sender" in observation["typed_fact"]["schema"]["canonical_fields"]

        accepted = payload["accepted_facts_delta"]
        assert accepted
        assert accepted[0]["typed_fact"]["schema"]["version"] == "fact-family/email/v1"
        assert "required_provenance" in accepted[0]["typed_fact"]["schema"]

    def test_observation_normalizer_emits_typed_email_delivery_envelope(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-email",
            tool_name="analyze_email",
            params={"message_id": "msg-22"},
            result={
                "sender": "attacker@example.com",
                "recipient": "alice@corp.local",
                "attachment": "invoice.zip",
                "severity": "high",
            },
            step_number=4,
        )

        assert payload["observations"]
        observation = payload["observations"][0]
        assert observation["observation_type"] == "email_delivery"
        assert observation["fact_family"] == "email"
        assert observation["schema_version"] == "typed-observation/v1"
        assert observation["typed_fact"]["family"] == "email"
        assert observation["typed_fact"]["type"] == "email_delivery"
        assert observation["provenance"]["source_kind"] == "tool_result"
        assert observation["extraction_method"] == "normalizer"
        assert any(entity["type"] in {"user", "email"} for entity in observation["entities"])


    def test_observation_normalizer_emits_typed_sandbox_behavior_envelope(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-sandbox",
            tool_name="sandbox_sample",
            params={"sha256": "a" * 64},
            result={
                "verdict": "MALICIOUS",
                "threat_score": 91,
                "process_name": "rundll32.exe",
                "domain": "evil.example",
            },
            step_number=5,
        )

        assert payload["observations"]
        observation = payload["observations"][0]
        assert observation["observation_type"] == "sandbox_behavior"
        assert observation["fact_family"] == "file"
        assert observation["schema_version"] == "typed-observation/v1"
        assert observation["typed_fact"]["family"] == "file"
        assert observation["typed_fact"]["type"] == "sandbox_behavior"
        assert observation["provenance"]["source_kind"] == "tool_result"
        assert observation["quality_semantics"]["family"] == "file"


    def test_observation_normalizer_enriches_accepted_facts_with_provenance_fields(self):
        normalizer = ObservationNormalizer()

        payload = normalizer.normalize(
            session_id="sess-ioc",
            tool_name="investigate_ioc",
            params={"ioc": "185.220.101.45"},
            result={
                "ioc": "185.220.101.45",
                "verdict": "MALICIOUS",
                "threat_score": 98,
                "severity": "high",
            },
            step_number=1,
        )

        accepted = payload["accepted_facts_delta"]
        assert accepted
        fact = accepted[0]
        assert fact["observation_type"] == "ioc_enrichment"
        assert fact["fact_family"] == "ioc"
        assert fact["source_kind"] == "tool_result"
        assert fact["source_paths"] == ["result"]
        assert fact["extraction_method"] == "normalizer"
        assert fact["timestamp"]
        assert fact["produced_at"]

    def test_root_cause_engine_marks_weak_evidence_as_insufficient(self):
        engine = RootCauseEngine()

        assessment = engine.assess(
            goal="Investigate suspicious email delivery",
            reasoning_state={
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "statement": "Initial access likely occurred through phishing.",
                        "confidence": 0.58,
                        "priority": 0.58,
                        "evidence_score": 0.12,
                        "contradiction_score": 0.04,
                        "supporting_evidence_refs": [],
                        "contradicting_evidence_refs": [],
                    }
                ],
                "missing_evidence": ["Need delivery evidence tied to the target mailbox."],
                "open_questions": ["Was the email delivered to the user?"],
            },
            deterministic_decision={"verdict": "SUSPICIOUS"},
            evidence_state={"timeline": []},
            active_observations=[],
            unresolved_questions=["Was the email delivered to the user?"],
        )

        assert assessment["status"] == "insufficient_evidence"
        assert "Insufficient evidence" in assessment["summary"] or "lacks" in assessment["summary"]

    def test_root_cause_engine_promotes_supported_status_with_explicit_relations(self):
        engine = RootCauseEngine()

        assessment = engine.assess(
            goal="Investigate suspicious login sequence",
            reasoning_state={
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "statement": "Credential misuse or session abuse is the strongest specialized hypothesis.",
                        "confidence": 0.78,
                        "priority": 0.9,
                        "evidence_score": 0.42,
                        "contradiction_score": 0.08,
                        "supporting_evidence_refs": [
                            {
                                "observation_id": "obs-auth-1",
                                "summary": "Auth telemetry tied alice to session LOGON-22 from 185.220.101.45 on WS-12.",
                                "quality": 0.78,
                            }
                        ],
                        "contradicting_evidence_refs": [],
                    },
                    {
                        "id": "hyp-2",
                        "statement": "The activity is benign administrative noise.",
                        "confidence": 0.41,
                        "priority": 0.41,
                        "evidence_score": 0.1,
                        "contradiction_score": 0.16,
                        "supporting_evidence_refs": [],
                        "contradicting_evidence_refs": [],
                    },
                ],
                "missing_evidence": [],
                "open_questions": [],
            },
            deterministic_decision={"verdict": "SUSPICIOUS"},
            evidence_state={
                "timeline": [
                    {"summary": "User alice authenticated to WS-12."},
                    {"summary": "Session LOGON-22 initiated outbound activity."},
                ]
            },
            entity_state={
                "relationships": [
                    {
                        "source": "session:logon-22",
                        "target": "user:alice",
                        "relation": "belongs_to",
                        "relation_strength": "explicit",
                    },
                    {
                        "source": "session:logon-22",
                        "target": "ip:185.220.101.45",
                        "relation": "authenticated_from",
                        "relation_strength": "explicit",
                    },
                ]
            },
            active_observations=[
                {
                    "observation_id": "obs-auth-1",
                    "summary": "Auth telemetry tied alice to session LOGON-22 from 185.220.101.45 on WS-12.",
                    "quality": 0.78,
                }
            ],
        )

        assert assessment["status"] == "supported"
        assert assessment["confidence"] >= 0.78
        assert any("Relationship belongs_to links session:logon-22 to user:alice (explicit)." == item for item in assessment["causal_chain"])
        assert any("Deterministic verdict remains SUSPICIOUS." == item for item in assessment["causal_chain"])

    def test_root_cause_engine_keeps_high_gap_pressure_as_insufficient_without_explicit_relations(self):
        engine = RootCauseEngine()

        assessment = engine.assess(
            goal="Investigate suspicious login sequence",
            reasoning_state={
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "statement": "Credential misuse or session abuse is the strongest specialized hypothesis.",
                        "confidence": 0.7,
                        "priority": 0.78,
                        "evidence_score": 0.31,
                        "contradiction_score": 0.06,
                        "supporting_evidence_refs": [
                            {"summary": "Suspicious auth event observed.", "quality": 0.6}
                        ],
                        "contradicting_evidence_refs": [],
                    }
                ],
                "missing_evidence": ["Need explicit user, host, session, and process linkage."],
                "open_questions": ["Which entities can be linked with explicit evidence rather than co-observation alone?"],
            },
            deterministic_decision={"verdict": "SUSPICIOUS"},
            evidence_state={"timeline": [{"summary": "Suspicious auth event observed."}]},
            entity_state={
                "relationships": [
                    {
                        "source": "user:alice",
                        "target": "host:ws-12",
                        "relation": "co_observed",
                        "relation_strength": "co_observed",
                    }
                ]
            },
            active_observations=[],
        )

        assert assessment["status"] == "insufficient_evidence"
        assert "Highest-priority gap" in assessment["summary"]


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
        assert any(item["type"] == "host" and item["canonical_value"] == "ws-12" for item in entities.values())
        assert any(rel["relation"] == "co_observed" for rel in state["relationships"])
        assert all(rel["explicit"] is False for rel in state["relationships"])
        assert all(rel["relation_strength"] == "co_observed" for rel in state["relationships"])

    def test_entity_resolver_derives_typed_auth_and_process_relations(self):
        resolver = EntityResolver()
        state = resolver.ingest_observation(
            None,
            session_id="sess-typed",
            tool_name="search_logs",
            params={"query": "user=alice"},
            result={"results": []},
            step_number=3,
            evidence_ref={
                "tool_name": "search_logs",
                "step_number": 3,
                "finding_index": 0,
                "summary": "Alice authenticated on WS-12 and powershell connected outward.",
                "created_at": "2026-04-18T00:00:00+00:00",
            },
            observations=[
                {
                    "observation_id": "obs-auth-1",
                    "observation_type": "auth_event",
                    "summary": "Auth event",
                    "source_kind": "log_row",
                    "source_paths": ["result.results[0]"],
                    "timestamp": "2026-04-18T00:00:00+00:00",
                    "entities": [
                        {"type": "user", "value": "alice", "label": "alice", "source_path": "result.results[0].user", "confidence": 0.9},
                        {"type": "host", "value": "WS-12", "label": "WS-12", "source_path": "result.results[0].host", "confidence": 0.9},
                        {"type": "session", "value": "LOGON-22", "label": "LOGON-22", "source_path": "result.results[0].session_id", "confidence": 0.9},
                        {"type": "ip", "value": "185.220.101.45", "label": "185.220.101.45", "source_path": "result.results[0].source_ip", "confidence": 0.95},
                    ],
                    "facts": {
                        "user": "alice",
                        "host": "WS-12",
                        "session_id": "LOGON-22",
                        "source_ip": "185.220.101.45",
                    },
                },
                {
                    "observation_id": "obs-proc-1",
                    "observation_type": "process_event",
                    "summary": "Process event",
                    "source_kind": "log_row",
                    "source_paths": ["result.results[1]"],
                    "timestamp": "2026-04-18T00:01:00+00:00",
                    "entities": [
                        {"type": "process", "value": "powershell.exe", "label": "powershell.exe", "source_path": "result.results[1].process_name", "confidence": 0.9},
                        {"type": "host", "value": "WS-12", "label": "WS-12", "source_path": "result.results[1].host", "confidence": 0.9},
                        {"type": "session", "value": "LOGON-22", "label": "LOGON-22", "source_path": "result.results[1].session_id", "confidence": 0.9},
                        {"type": "ip", "value": "185.220.101.45", "label": "185.220.101.45", "source_path": "result.results[1].dest_ip", "confidence": 0.95},
                    ],
                    "facts": {
                        "host": "WS-12",
                        "session_id": "LOGON-22",
                        "dest_ip": "185.220.101.45",
                        "process_name": "powershell.exe",
                    },
                },
            ],
        )

        relations = state["relationships"]
        assert any(rel["relation"] == "belongs_to" and rel["relation_strength"] == "explicit" for rel in relations)
        assert any(rel["relation"] == "authenticated_from" and rel["relation_basis"] == "auth_event:source_ip" for rel in relations)
        assert any(rel["relation"] == "derived_from" and rel["inferred"] is True for rel in relations)
        assert any(rel["relation"] == "connects_to" and rel["canonical_target"] == "ip:185.220.101.45" for rel in relations)

    def test_entity_resolver_derives_email_relations_with_sender_and_recipient(self):
        resolver = EntityResolver()
        state = resolver.ingest_observation(
            None,
            session_id="sess-email",
            tool_name="analyze_email",
            params={},
            result={},
            step_number=1,
            evidence_ref={
                "tool_name": "analyze_email",
                "step_number": 1,
                "finding_index": 0,
                "summary": "Email delivered from sender to recipient with attachment.",
                "created_at": "2026-04-18T02:00:00+00:00",
            },
            observations=[
                {
                    "observation_id": "obs-email-1",
                    "observation_type": "email_delivery",
                    "summary": "Email delivery observed",
                    "source_kind": "tool_result",
                    "source_paths": ["result"],
                    "timestamp": "2026-04-18T02:00:00+00:00",
                    "entities": [
                        {"type": "sender", "value": "attacker@example.com", "label": "attacker@example.com", "source_path": "result.sender", "confidence": 0.9},
                        {"type": "recipient", "value": "alice@example.com", "label": "alice@example.com", "source_path": "result.recipient", "confidence": 0.9},
                        {"type": "domain", "value": "example.com", "label": "example.com", "source_path": "result.sender_domain", "confidence": 0.85},
                        {"type": "file", "value": "invoice.zip", "label": "invoice.zip", "source_path": "result.attachment", "confidence": 0.8},
                    ],
                    "facts": {
                        "sender": "attacker@example.com",
                        "recipient": "alice@example.com",
                        "domain": "example.com",
                        "attachment": "invoice.zip",
                    },
                }
            ],
        )

        entities = state["entities"]
        assert "sender:attacker@example.com" in entities
        assert "recipient:alice@example.com" in entities
        assert any(rel["relation"] == "received_from" and rel["explicit"] is True for rel in state["relationships"])
        assert any(rel["relation"] == "received_attachment" and rel["inferred"] is True for rel in state["relationships"])
        assert any(rel["relation"] == "originates_from" for rel in state["relationships"])

    def test_entity_resolver_exposes_canonical_entity_and_relation_vocab(self):
        resolver = EntityResolver()

        state = resolver.bootstrap()

        assert "user" in state["canonical_entity_types"]
        assert "host" in state["canonical_entity_types"]
        assert "session" in state["canonical_entity_types"]
        assert "connects_to" in state["canonical_relation_types"]
        assert "co_observed" in state["canonical_relation_types"]

    def test_entity_resolver_normalizes_alias_entity_types_into_canonical_types(self):
        resolver = EntityResolver()
        state = resolver.ingest_observation(
            None,
            session_id="sess-alias",
            tool_name="search_logs",
            params={},
            result={},
            step_number=0,
            evidence_ref={
                "session_id": "sess-alias",
                "step_number": 0,
                "finding_index": 0,
                "tool_name": "search_logs",
                "summary": "Observed hostname and account aliases",
                "created_at": "2026-04-19T00:00:00+00:00",
            },
            observations=[
                {
                    "observation_id": "obs:sess-alias:0:0",
                    "observation_type": "auth_event",
                    "summary": "Hostname WS-12 authenticated as alice",
                    "source_kind": "log_row",
                    "source_paths": ["result.rows[0]"],
                    "entities": [
                        {"type": "hostname", "value": "WS-12", "source_path": "result.rows[0].hostname", "confidence": 0.9},
                        {"type": "account", "value": "alice", "source_path": "result.rows[0].account", "confidence": 0.9},
                        {"type": "session", "value": "logon-1", "source_path": "result.rows[0].session", "confidence": 0.9},
                    ],
                    "facts": {"host": "WS-12", "user": "alice", "session_id": "logon-1"},
                }
            ],
        )

        entities = state["entities"]
        assert "host:ws-12" in entities
        assert "user:alice" in entities
        assert entities["host:ws-12"]["attributes"]["entity_family"] == "endpoint"
        assert entities["user:alice"]["attributes"]["entity_family"] == "identity"

    def test_entity_resolver_uses_typed_network_fact_when_observation_type_is_generic(self):
        resolver = EntityResolver()
        state = resolver.ingest_observation(
            None,
            session_id="sess-network-typed",
            tool_name="correlate_findings",
            params={},
            result={},
            step_number=2,
            evidence_ref={
                "tool_name": "correlate_findings",
                "step_number": 2,
                "finding_index": 0,
                "summary": "Network evidence links WS-12 to rare-c2.example and 203.0.113.50.",
                "created_at": "2026-04-18T03:00:00+00:00",
            },
            observations=[
                {
                    "observation_id": "obs-network-typed-1",
                    "observation_type": "correlation_observation",
                    "fact_family": "network",
                    "typed_fact": {"family": "network", "type": "network_event"},
                    "summary": "Network evidence observed",
                    "source_kind": "tool_result",
                    "source_paths": ["result"],
                    "timestamp": "2026-04-18T03:00:00+00:00",
                    "entities": [
                        {"type": "host", "value": "WS-12", "label": "WS-12", "source_path": "result.host", "confidence": 0.9},
                        {"type": "ip", "value": "203.0.113.50", "label": "203.0.113.50", "source_path": "result.dest_ip", "confidence": 0.95},
                        {"type": "domain", "value": "rare-c2.example", "label": "rare-c2.example", "source_path": "result.domain", "confidence": 0.9},
                    ],
                    "facts": {
                        "host": "WS-12",
                        "dest_ip": "203.0.113.50",
                        "domain": "rare-c2.example",
                    },
                }
            ],
        )

        relations = state["relationships"]
        assert any(rel["relation"] == "connects_to" and rel["canonical_source"] == "host:ws-12" and rel["canonical_target"] == "ip:203.0.113.50" for rel in relations)
        assert any(rel["relation"] == "connects_to" and rel["canonical_source"] == "host:ws-12" and rel["canonical_target"] == "domain:rare-c2.example" for rel in relations)

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

    def test_evidence_graph_preserves_typed_network_observation_metadata(self):
        graph = EvidenceGraph()
        graph_state = graph.ingest_observation(
            None,
            session_id="sess-graph-network",
            tool_name="correlate_findings",
            step_number=2,
            evidence_ref={
                "tool_name": "correlate_findings",
                "step_number": 2,
                "finding_index": 0,
                "summary": "Network evidence links WS-12 to rare-c2.example.",
                "created_at": "2026-04-18T03:00:00+00:00",
            },
            entity_state={
                "entities": {
                    "host:ws-12": {"id": "host:ws-12", "type": "host", "value": "WS-12", "label": "WS-12"},
                    "domain:rare-c2.example": {"id": "domain:rare-c2.example", "type": "domain", "value": "rare-c2.example", "label": "rare-c2.example"},
                }
            },
            observations=[
                {
                    "observation_id": "obs-network-graph-1",
                    "observation_type": "correlation_observation",
                    "fact_family": "network",
                    "typed_fact": {"family": "network", "type": "network_event"},
                    "summary": "Network evidence observed",
                    "timestamp": "2026-04-18T03:00:00+00:00",
                    "quality": 0.72,
                    "source_paths": ["result"],
                    "entities": [
                        {"type": "host", "value": "WS-12"},
                        {"type": "domain", "value": "rare-c2.example"},
                    ],
                    "facts": {"host": "WS-12", "domain": "rare-c2.example"},
                }
            ],
        )

        observation_nodes = [node for node in graph_state["nodes"] if node["id"] == "obs-network-graph-1"]
        assert observation_nodes
        node = observation_nodes[0]
        assert node["observation_type"] == "correlation_observation"
        assert node["fact_family"] == "network"
        assert node["typed_fact"]["family"] == "network"
        assert node["typed_fact"]["type"] == "network_event"


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

    def test_chat_opening_capability_prompt_is_left_for_model_response(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        session_id = loop.store.create_session(
            goal="Hello, what can you help me investigate in SOC workflows?",
            metadata={"chat_mode": True, "response_style": "conversational"},
        )
        state = AgentState(
            session_id=session_id,
            goal="Hello, what can you help me investigate in SOC workflows?",
            max_steps=4,
        )

        decision = loop._chat_short_circuit_decision(state)

        assert decision is None
        assert loop._chat_should_force_model_answer_without_tools(state) is True

    def test_chat_short_circuit_bootstraps_simple_ioc_chat_to_investigate_ioc(self, tmp_path):
        loop = _make_agent_loop(tmp_path)

        async def investigate_ioc(**kwargs):
            return {"verdict": "UNKNOWN"}

        async def search_logs(**kwargs):
            return {"results_count": 0, "results": []}

        loop.tools.register_local_tool(
            name="investigate_ioc",
            description="Investigate IOC",
            parameters={"properties": {"ioc": {"type": "string"}}},
            category="analysis",
            executor=investigate_ioc,
        )
        loop.tools.register_local_tool(
            name="search_logs",
            description="Search logs",
            parameters={"properties": {"query": {"type": "string"}}},
            category="siem",
            executor=search_logs,
        )

        session_id = loop.store.create_session(
            goal="Check 8.8.8.8 and tell me if it looks suspicious.",
            metadata={"chat_mode": True, "response_style": "conversational"},
        )
        state = AgentState(
            session_id=session_id,
            goal="Check 8.8.8.8 and tell me if it looks suspicious.",
            max_steps=4,
        )

        decision = loop._chat_short_circuit_decision(state)

        assert decision is not None
        assert decision["action"] == "use_tool"
        assert decision["tool"] == "investigate_ioc"
        assert decision["params"] == {"ioc": "8.8.8.8"}

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
        assert decision is None
        assert loop._chat_should_force_model_answer_without_tools(state) is True

    def test_simple_chat_clean_verdict_with_enrichment_short_circuits_without_llm(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        session_id = loop.store.create_session(
            goal="Check 8.8.8.8 and tell me if it looks suspicious.",
            metadata={"chat_mode": True, "response_style": "conversational"},
        )
        state = AgentState(
            session_id=session_id,
            goal="Check 8.8.8.8 and tell me if it looks suspicious.",
            max_steps=4,
        )

        state.add_finding(
            {
                "type": "tool_result",
                "tool": "investigate_ioc",
                "params": {"ioc": "8.8.8.8"},
                "result": {"ioc": "8.8.8.8", "verdict": "CLEAN", "threat_score": 10},
            }
        )
        loop._refresh_reasoning_outputs(
            session_id,
            state,
            tool_name="investigate_ioc",
            params={"ioc": "8.8.8.8"},
            result={"ioc": "8.8.8.8", "verdict": "CLEAN", "threat_score": 10},
        )
        state.step_count += 1

        state.add_finding(
            {
                "type": "tool_result",
                "tool": "network-analysis.geoip_lookup",
                "params": {"ip": "8.8.8.8"},
                "result": {
                    "result": {
                        "ip": "8.8.8.8",
                        "organization": "Google",
                        "reverse_dns": "dns.google",
                    }
                },
            }
        )
        loop._refresh_reasoning_outputs(
            session_id,
            state,
            tool_name="network-analysis.geoip_lookup",
            params={"ip": "8.8.8.8"},
            result={
                "result": {
                    "ip": "8.8.8.8",
                    "organization": "Google",
                    "reverse_dns": "dns.google",
                }
            },
        )
        state.step_count += 1

        async def correlate_findings(**kwargs):
            return {
                "severity": "low",
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
        assert any(edge["relation"] in {"authenticated_from", "belongs_to", "occurred_on"} for edge in graph["edges"])
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
