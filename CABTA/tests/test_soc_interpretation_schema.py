import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_ontology import CapabilityOntology
from src.agent.soc_interpretation_schema import (
    SOCInterpretation,
    compact_for_task_state,
    validate_soc_interpretation,
)


def _valid_payload():
    return {
        "schema_version": "soc-interpretation/v1",
        "raw_request": "Can you triage 185.220.101.45 and show evidence?",
        "normalized_request": "can you triage 185.220.101.45 and show evidence?",
        "conversation_role": "new_task",
        "primary_intent": "ioc_triage",
        "lane": "ioc",
        "objectives": [
            {
                "objective_type": "triage",
                "summary": "Triage the IP address with deterministic threat intelligence.",
                "rationale": "The analyst supplied an IP and asked for evidence.",
                "priority": "primary",
                "lane": "ioc",
                "requires_fresh_evidence": True,
                "success_criteria": ["IOC enrichment is completed or degraded honestly."],
                "forbidden_claims": ["Do not claim malicious without deterministic evidence."],
                "confidence": 0.91,
            }
        ],
        "entities": [
            {
                "type": "ip",
                "value": "185.220.101.45",
                "role": "observable",
                "source": "user_message",
                "confidence": 0.95,
                "sanity_status": "matched_deterministic_extractor",
            }
        ],
        "capability_needs": [
            {
                "capability_id": "ioc.enrich",
                "need_type": "enrich_ioc",
                "priority": "required",
                "reason": "IOC triage requires deterministic enrichment.",
                "required_inputs": ["ioc_value"],
                "expected_outputs": ["reputation", "sources"],
                "blocking": True,
                "confidence": 0.94,
            }
        ],
        "missing_inputs": [],
        "approval_needs": [],
        "requested_backends": [],
        "timerange": {"requested": "24h", "effective": "24h", "source": "default"},
        "artifacts": [],
        "output_preferences": ["summary"],
        "safety_flags": [],
        "confidence": 0.92,
        "confidence_label": "high",
        "provenance": {"interpreter": "llm-request-interpreter/v1", "feature_flag_mode": "primary"},
        "raw_llm_output": {"kept": "for audit"},
        "validation": {"authoritative_for_verdict": False},
        "repair": {"attempted": False, "attempt_count": 0, "final_status": "not_needed"},
        "fallback": {"used": False},
    }


def test_valid_interpretation_round_trips_and_keeps_audit_metadata():
    interpretation, validation = validate_soc_interpretation(_valid_payload(), CapabilityOntology())

    assert validation.valid is True
    assert interpretation is not None
    round_tripped = SOCInterpretation.from_dict(interpretation.to_dict())
    assert round_tripped.raw_request == _valid_payload()["raw_request"]
    assert round_tripped.capability_needs[0].capability_id == "ioc.enrich"
    assert round_tripped.validation["authoritative_for_verdict"] is False
    assert round_tripped.raw_llm_output == {"kept": "for audit"}


def test_invalid_enum_capability_and_confidence_fail_structured_validation():
    payload = _valid_payload()
    payload["primary_intent"] = "make_verdict_now"
    payload["confidence"] = 1.7
    payload["capability_needs"][0]["capability_id"] = "shell.execute"

    interpretation, validation = validate_soc_interpretation(payload, CapabilityOntology())

    assert interpretation is None
    assert validation.valid is False
    assert "invalid_primary_intent" in validation.errors
    assert "invalid_confidence" in validation.errors
    assert "unknown_capability:shell.execute" in validation.errors
    assert validation.capability_status == "invalid"


def test_approval_needs_are_forced_non_executable():
    payload = _valid_payload()
    payload["primary_intent"] = "incident_response"
    payload["lane"] = "incident_response"
    payload["capability_needs"] = [
        {
            "capability_id": "ir.user.disable.propose",
            "need_type": "propose_response_action",
            "priority": "required",
            "reason": "User asked to disable account after evidence.",
            "required_inputs": ["target", "evidence_refs"],
            "expected_outputs": ["approval_status"],
            "blocking": True,
            "confidence": 0.87,
        }
    ]
    payload["approval_needs"] = [
        {
            "action_type": "disable_user",
            "capability_id": "ir.user.disable.propose",
            "target_type": "user",
            "target": "alice",
            "evidence_required": ["supporting evidence"],
            "approval_required": True,
            "execution_allowed": True,
            "reason": "Prompt attempted to force execution.",
            "confidence": 0.85,
        }
    ]
    payload["safety_flags"] = ["destructive_action_requested"]

    interpretation, validation = validate_soc_interpretation(payload, CapabilityOntology())

    assert interpretation is not None
    approval = interpretation.approval_needs[0]
    assert approval.approval_required is True
    assert approval.execution_allowed is False
    assert validation.safety_status == "needs_approval"


def test_compact_for_task_state_excludes_raw_llm_output():
    interpretation, validation = validate_soc_interpretation(_valid_payload(), CapabilityOntology())
    compact = compact_for_task_state(interpretation)

    assert compact["schema_version"] == "soc-interpretation/v1"
    assert compact["primary_intent"] == "ioc_triage"
    assert compact["validation"]["authoritative_for_verdict"] is False
    assert "raw_llm_output" not in compact
