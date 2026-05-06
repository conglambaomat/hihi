import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.soc_task_state import SOCTaskState


def test_soc_task_state_serializes_and_restores_followup_link():
    state = SOCTaskState(session_id="s1", parent_task_id="parent", raw_request="What did you find?", conversation_role="follow_up")
    restored = SOCTaskState.from_dict(state.to_dict())
    assert restored.parent_task_id == "parent"
    assert restored.conversation_role == "follow_up"
    assert restored.task_id


def test_soc_task_state_preserves_field_sources_and_confidence():
    state = SOCTaskState(raw_request="triage 185.220.101.45")
    state.add_entity("ip", "185.220.101.45", source="message", confidence=0.91)
    assert state.entities[0]["confidence"] == 0.91
    assert state.field_sources["entities"][0]["source"] == "message"


def test_soc_task_state_loads_from_legacy_reasoning_state_safely():
    restored = SOCTaskState.from_legacy_reasoning_state({"objective_contract": {"lane": "ioc", "objective_type": "ioc_triage", "entities": [{"type": "ip", "value": "1.1.1.1"}], "capabilities_required": ["ioc.enrich"]}}, session_id="s2")
    assert restored.session_id == "s2"
    assert restored.lane == "ioc"
    assert restored.required_capabilities == ["ioc.enrich"]
