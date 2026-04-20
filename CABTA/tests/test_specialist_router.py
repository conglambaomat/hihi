import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.specialist_router import SpecialistRouter


class _Profiles:
    def __init__(self, valid_profiles):
        self.valid_profiles = set(valid_profiles)

    def get_profile(self, profile_id):
        return {"id": profile_id} if profile_id in self.valid_profiles else None


class _WorkflowRegistry:
    def __init__(self, workflows):
        self.workflows = workflows

    def get_workflow(self, workflow_id):
        return self.workflows.get(workflow_id)


def _build_state(**overrides):
    state = SimpleNamespace(
        specialist_team=["triage", "investigator", "correlator"],
        active_specialist="triage",
        agent_profile_id="triage",
        specialist_index=0,
        specialist_handoffs=[],
        max_steps=6,
        step_count=3,
        active_observations=[],
        unresolved_questions=[],
        agentic_explanation={},
        investigation_plan={},
        entity_state={},
        accepted_facts=[],
    )

    def record_specialist_handoff(from_profile, to_profile, reason):
        state.active_specialist = to_profile
        state.agent_profile_id = to_profile
        state.specialist_index = state.specialist_team.index(to_profile)
        handoff = {
            "from_profile": from_profile,
            "to_profile": to_profile,
            "reason": reason,
        }
        state.specialist_handoffs.append(handoff)
        return handoff

    state.record_specialist_handoff = record_specialist_handoff

    for key, value in overrides.items():
        setattr(state, key, value)
    return state


def test_resolve_specialist_team_merges_requested_and_workflow_profiles():
    router = SpecialistRouter(
        workflow_registry=_WorkflowRegistry(
            {
                "wf-1": {
                    "agents": ["triage", "investigator", "triage", "unknown_profile"],
                }
            }
        ),
        agent_profiles=_Profiles({"triage", "investigator", "correlator"}),
    )

    result = router.resolve_specialist_team(
        {
            "workflow_id": "wf-1",
            "specialist_team": ["correlator", "triage"],
            "agent_profile_id": "investigator",
        }
    )

    assert result == ["correlator", "triage", "investigator"]


def test_specialist_index_from_evidence_prefers_first_matching_investigator_when_root_cause_supported():
    router = SpecialistRouter()
    state = _build_state(
        agentic_explanation={
            "root_cause_assessment": {"status": "supported"},
            "missing_evidence": [],
        }
    )

    assert router.specialist_index_from_evidence(state) == 1


def test_assess_specialist_routing_returns_explainable_supported_root_cause_metadata():
    router = SpecialistRouter()
    state = _build_state(
        agentic_explanation={
            "root_cause_assessment": {"status": "supported"},
            "missing_evidence": [],
        }
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 1
    assert assessment["selected_profile"] == "investigator"
    assert assessment["reason"] == "supported_root_cause"
    assert assessment["winning_score"] == 1
    assert assessment["tie_detected"] is False
    assert assessment["ranked_candidates"] == [
        {
            "profile": "investigator",
            "score": 1,
            "reasons": ["supported_root_cause"],
        }
    ]
    assert assessment["signals"]["root_cause_status"] == "supported"


def test_specialist_index_from_evidence_prefers_identity_specialist_for_auth_signals():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "network_forensics"],
        active_observations=[{"observation_type": "auth_event"}],
        investigation_plan={"lane": "log_identity"},
        entity_state={"entities": {"u1": {"type": "user", "value": "alice"}}},
    )

    assert router.specialist_index_from_evidence(state) == 1


def test_specialist_index_from_evidence_prefers_email_specialist_for_explicit_delivery_relations():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "phish_analyst", "network_forensics"],
        active_observations=[{"observation_type": "email_delivery"}],
        entity_state={
            "entities": {
                "sender:attacker@example.com": {"type": "sender", "value": "attacker@example.com"},
                "recipient:alice@example.com": {"type": "recipient", "value": "alice@example.com"},
            },
            "relationships": [
                {"relation": "received_from", "relation_strength": "explicit"},
                {"relation": "received_attachment", "relation_strength": "inferred"},
            ],
        },
    )

    assert router.specialist_index_from_evidence(state) == 1


def test_specialist_index_from_evidence_prefers_malware_specialist_for_top_process_gap():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "malware_endpoint"],
        active_observations=[{"observation_type": "network_event"}],
        agentic_explanation={
            "missing_evidence": ["Need process execution evidence to confirm payload behavior."],
            "root_cause_assessment": {"status": "inconclusive"},
        },
        entity_state={
            "entities": {
                "ip:185.220.101.45": {"type": "ip", "value": "185.220.101.45"},
            }
        },
    )

    assert router.specialist_index_from_evidence(state) == 2


def test_assess_specialist_routing_exposes_scores_and_signal_reasons():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "malware_endpoint"],
        active_observations=[{"observation_type": "network_event"}],
        agentic_explanation={
            "missing_evidence": ["Need process execution evidence to confirm payload behavior."],
            "root_cause_assessment": {"status": "inconclusive"},
        },
        entity_state={
            "entities": {
                "ip:185.220.101.45": {"type": "ip", "value": "185.220.101.45"},
            }
        },
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 2
    assert assessment["selected_profile"] == "malware_endpoint"
    assert assessment["reason"] == "evidence_signal_match"
    assert assessment["winning_score"] == assessment["scores"]["malware_endpoint"]["score"]
    assert assessment["tie_detected"] is False
    assert assessment["ranked_candidates"][0]["profile"] == "malware_endpoint"
    assert assessment["ranked_candidates"][0]["score"] == assessment["scores"]["malware_endpoint"]["score"]
    assert "top_gap_process_execution" in assessment["ranked_candidates"][0]["reasons"]
    assert assessment["signals"]["top_gap"].startswith("need process execution evidence")
    assert assessment["scores"]["malware_endpoint"]["score"] >= 4
    assert "top_gap_process_execution" in assessment["scores"]["malware_endpoint"]["reasons"]


def test_assess_specialist_routing_uses_network_fact_family_signal():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "network_forensics"],
        active_observations=[
            {
                "observation_type": "correlation_observation",
                "fact_family": "network",
                "typed_fact": {"family": "network", "type": "network_event"},
            }
        ],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
        entity_state={"entities": {}, "relationships": []},
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 2
    assert assessment["selected_profile"] == "network_forensics"
    assert "network" in assessment["signals"]["fact_families"]
    assert "network_signals" in assessment["scores"]["network_forensics"]["reasons"]


def test_specialist_index_from_evidence_uses_triage_when_only_co_observed_relationships_exist():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "email_analyst", "malware_endpoint"],
        entity_state={
            "entities": {
                "user:alice": {"type": "user", "value": "alice"},
                "host:ws-12": {"type": "host", "value": "WS-12"},
            },
            "relationships": [
                {"relation": "co_observed", "relation_strength": "co_observed"},
            ],
        },
        active_observations=[],
        accepted_facts=[],
        unresolved_questions=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
    )

    assert router.specialist_index_from_evidence(state) == 0


def test_assess_specialist_routing_uses_active_hypothesis_topics_for_identity_bias():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "network_forensics"],
        reasoning_state={
            "investigation_lane": "log_identity",
            "hypotheses": [
                {
                    "statement": "Credential misuse or session abuse is the strongest specialized hypothesis.",
                    "status": "open",
                    "topics": ["identity", "credential", "session"],
                    "open_questions": ["Which user and session are explicitly linked?"],
                }
            ],
        },
        active_observations=[],
        unresolved_questions=[],
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 1
    assert assessment["selected_profile"] == "identity_investigator"
    assert assessment["signals"]["active_hypothesis_topics"] == ["credential", "identity", "session"]
    assert assessment["signals"]["active_hypothesis_status"] == "open"
    assert assessment["scores"]["identity_investigator"]["score"] >= 4
    assert "identity_signals" in assessment["scores"]["identity_investigator"]["reasons"]


def test_assess_specialist_routing_uses_fact_family_email_signal():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "phish_analyst", "network_forensics"],
        active_observations=[
            {
                "summary": "Email delivery telemetry",
                "fact_family": "email",
                "typed_fact": {"family": "email", "type": "unknown"},
            }
        ],
        unresolved_questions=[],
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 1
    assert assessment["selected_profile"] == "phish_analyst"
    assert assessment["signals"]["fact_families"] == ["email"]
    assert assessment["scores"]["phish_analyst"]["score"] >= 5
    assert "email_lane_or_entities" in assessment["scores"]["phish_analyst"]["reasons"]


def test_assess_specialist_routing_uses_fact_family_ioc_signal():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "network_forensics"],
        active_observations=[
            {
                "summary": "IOC enrichment links destination infrastructure",
                "typed_fact": {"family": "ioc", "type": "unknown"},
            }
        ],
        unresolved_questions=[],
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 2
    assert assessment["selected_profile"] == "network_forensics"
    assert assessment["signals"]["fact_families"] == ["ioc"]
    assert assessment["scores"]["network_forensics"]["score"] >= 4
    assert "network_signals" in assessment["scores"]["network_forensics"]["reasons"]


def test_assess_specialist_routing_uses_fact_family_vulnerability_signal():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "vuln_exposure_specialist", "correlator"],
        active_observations=[
            {
                "summary": "Asset exposure maps to known CVE activity",
                "fact_family": "vulnerability",
                "typed_fact": {"family": "vulnerability", "type": "vulnerability_exposure"},
            }
        ],
        unresolved_questions=[],
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 1
    assert assessment["selected_profile"] == "vuln_exposure_specialist"
    assert assessment["signals"]["fact_families"] == ["vulnerability"]
    assert assessment["scores"]["vuln_exposure_specialist"]["score"] >= 4
    assert "vulnerability_signals" in assessment["scores"]["vuln_exposure_specialist"]["reasons"]


def test_assess_specialist_routing_uses_active_hypothesis_text_for_malware_bias():
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage", "identity_investigator", "malware_endpoint"],
        reasoning_state={
            "hypotheses": [
                {
                    "statement": "Malware payload execution is likely central to this case.",
                    "status": "supported",
                    "topics": [],
                    "open_questions": ["Do sandbox and process execution artifacts confirm payload behavior?"],
                }
            ],
        },
        active_observations=[],
        unresolved_questions=[],
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "inconclusive"}},
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 2
    assert assessment["selected_profile"] == "malware_endpoint"
    assert assessment["signals"]["active_hypothesis_status"] == "supported"
    assert assessment["scores"]["malware_endpoint"]["score"] >= 5
    assert "malware_execution_signals" in assessment["scores"]["malware_endpoint"]["reasons"]


def test_assess_specialist_routing_returns_stay_with_current_specialist_when_state_is_empty_and_owner_is_valid():
    router = SpecialistRouter()
    state = _build_state(
        active_observations=[],
        unresolved_questions=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
        investigation_plan={},
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        active_specialist="triage",
        specialist_index=0,
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] == 0
    assert assessment["selected_profile"] == "triage"
    assert assessment["reason"] == "stay_with_current_specialist"
    assert assessment["scores"] == {}


def test_assess_specialist_routing_returns_no_signal_when_state_is_empty_and_owner_is_invalid():
    router = SpecialistRouter()
    state = _build_state(
        active_observations=[],
        unresolved_questions=[],
        agentic_explanation={"missing_evidence": [], "root_cause_assessment": {"status": "collecting"}},
        investigation_plan={},
        entity_state={"entities": {}, "relationships": []},
        accepted_facts=[],
        active_specialist="unknown_specialist",
        specialist_index=99,
    )

    assessment = router.assess_specialist_routing(state)

    assert assessment["selected_index"] is None
    assert assessment["selected_profile"] is None
    assert assessment["reason"] == "no_evidence_signal"
    assert assessment["scores"] == {}


def test_sync_specialist_progress_keeps_current_specialist_when_no_stronger_evidence_signal_exists():
    notify = MagicMock()
    log_decision = MagicMock()
    store = MagicMock()
    persist_specialist_metadata = MagicMock()
    router = SpecialistRouter(notify=notify, log_decision=log_decision)
    state = _build_state()

    router.sync_specialist_progress(
        session_id="sess-1",
        state=state,
        store=store,
        persist_specialist_metadata=persist_specialist_metadata,
        reason="",
    )

    assert state.active_specialist == "triage"
    assert state.agent_profile_id == "triage"
    assert state.specialist_index == 0
    assert state.specialist_handoffs == []
    store.add_step.assert_not_called()
    notify.assert_not_called()
    log_decision.assert_not_called()
    persist_specialist_metadata.assert_called_once_with(
        "sess-1",
        state,
        reason="stay_with_current_specialist",
    )


def test_sync_specialist_progress_falls_back_to_workflow_progress_when_current_owner_is_invalid():
    notify = MagicMock()
    log_decision = MagicMock()
    store = MagicMock()
    persist_specialist_metadata = MagicMock()
    router = SpecialistRouter(notify=notify, log_decision=log_decision)
    state = _build_state(
        active_specialist="unknown_specialist",
        specialist_index=99,
    )

    router.sync_specialist_progress(
        session_id="sess-1",
        state=state,
        store=store,
        persist_specialist_metadata=persist_specialist_metadata,
        reason="",
    )

    assert state.active_specialist == "investigator"
    assert state.agent_profile_id == "investigator"
    assert state.specialist_index == 1
    assert state.specialist_handoffs == [
        {
            "from_profile": "unknown_specialist",
            "to_profile": "investigator",
            "reason": "Workflow progression moved ownership to specialist phase 2",
        }
    ]
    store.add_step.assert_called_once()
    notify.assert_called_once_with(
        "sess-1",
        {
            "type": "specialist_handoff",
            "step": 3,
            "from_profile": "unknown_specialist",
            "to_profile": "investigator",
            "reason": "Workflow progression moved ownership to specialist phase 2",
        },
    )
    log_decision.assert_called_once()
    persist_specialist_metadata.assert_called_once_with(
        "sess-1",
        state,
        reason="Workflow progression moved ownership to specialist phase 2",
    )


def test_sync_specialist_progress_keeps_single_specialist_without_handoff():
    store = MagicMock()
    persist_specialist_metadata = MagicMock()
    router = SpecialistRouter()
    state = _build_state(
        specialist_team=["triage"],
        active_specialist="triage",
        agent_profile_id="triage",
        specialist_index=0,
        step_count=2,
    )

    router.sync_specialist_progress(
        session_id="sess-2",
        state=state,
        store=store,
        persist_specialist_metadata=persist_specialist_metadata,
        reason="Single specialist session",
    )

    assert state.active_specialist == "triage"
    assert state.agent_profile_id == "triage"
    assert state.specialist_index == 0
    assert state.specialist_handoffs == []
    store.add_step.assert_not_called()
    persist_specialist_metadata.assert_called_once_with("sess-2", state, reason="Single specialist session")