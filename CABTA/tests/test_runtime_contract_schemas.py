import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_actions import CapabilityAction
from src.agent.parameter_binder import ParameterBindingResult
from src.agent.preflight_validator import PreflightDecision
from src.agent.soc_task_state import SOCTaskState


def test_soc_task_state_contract_shape():
    payload = SOCTaskState(raw_request="hunt logs").to_dict()
    assert payload["schema_version"] == "soc-task-state/v1"
    assert "actions" in payload
    assert "progress_events" in payload


def test_capability_action_contract_shape():
    payload = CapabilityAction(capability_id="log.search").to_dict()
    assert payload["schema_version"] == "capability-action/v1"
    assert payload["params_schema"] == "log.search.params/v1"


def test_parameter_binding_contract_shape():
    payload = ParameterBindingResult(action_id="a1", params={"timerange": "24h"}).to_dict()
    assert payload["schema_version"] == "parameter-binding-result/v1"
    assert "missing_required" in payload


def test_preflight_decision_contract_shape():
    payload = PreflightDecision(allowed=True, status="allowed").to_dict()
    assert payload["schema_version"] == "preflight-decision/v1"
    assert payload["allowed"] is True
