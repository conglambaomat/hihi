import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_actions import make_action
from src.agent.parameter_binder import ParameterBinder
from src.agent.preflight_validator import PreflightValidator
from src.agent.request_understanding import SOCRequestInterpreter


def _preflight(message, capability):
    task = SOCRequestInterpreter().interpret(message)
    action = make_action(task, capability)
    binding = ParameterBinder().bind(action, task)
    return task, binding, PreflightValidator().validate(action, binding, task)


def test_preflight_blocks_missing_file_execution():
    task, binding, decision = _preflight(r"Analyze malware sample C:\Users\analyst\Downloads\invoice_update.exe but it was not uploaded", "file.analyze.static")
    assert decision.allowed is False
    assert decision.clarification_required is True
    assert "not uploaded" in "; ".join(decision.blocking_reasons)


def test_preflight_requires_approval_for_ir_actions():
    task, binding, decision = _preflight("Contain host WS-12 if evidence supports it; ask for approval", "ir.host.contain.propose")
    assert decision.allowed is False
    assert decision.approval_required is True


def test_preflight_preserves_explicit_timerange_over_tool_default():
    task, binding, decision = _preflight("Check Fortigate logs for outbound beaconing over the last 30 days", "log.search")
    assert decision.normalized_params["timerange"] == "30d"
    assert not any("overwrite" in reason for reason in decision.blocking_reasons)


def test_preflight_degrades_missing_log_backend_without_ioc_fallback():
    task, binding, decision = _preflight("Threat hunt for anything suspicious in our environment", "log.search")
    assert decision.allowed is True
    assert "ioc" not in decision.normalized_params
