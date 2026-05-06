import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.capability_actions import make_action
from src.agent.parameter_binder import ParameterBinder
from src.agent.request_understanding import SOCRequestInterpreter


def _bind(message, capability):
    task = SOCRequestInterpreter().interpret(message)
    action = make_action(task, capability)
    return task, ParameterBinder().bind(action, task)


def test_bind_log_search_splunk_failed_logons():
    task, binding = _bind("Search Splunk for failed logons followed by success for user alice on host WS-12 yesterday", "log.search")
    assert binding.params["backend"] == "splunk"
    assert binding.params["timerange"] == "yesterday"
    assert binding.params["query_intent"] == "failed logons followed by success"


def test_bind_fortigate_30d_beaconing_timerange():
    task, binding = _bind("Check Fortigate logs for outbound beaconing from 10.10.5.23 to 185.220.101.45 over the last 30 days", "log.search")
    assert binding.params["backend"] == "fortigate"
    assert binding.params["timerange"] == "30d"
    assert binding.params["requested_timerange"]["requested"] == "last_30_days"


def test_bind_inline_phishing_email_artifact():
    task, binding = _bind("Phishing email From: payroll@example.com Subject: Secure update link https://securecheck.example/login", "email.parse.inline")
    assert binding.params["sender"] == "payroll@example.com"
    assert binding.params["inline_email_ref"]
    assert not binding.params.get("file_path")


def test_bind_missing_windows_file_path_without_suffix():
    task, binding = _bind(r"Analyze sample C:\Users\analyst\Downloads\invoice_update.exe and tell me verdict; not uploaded", "file.analyze.static")
    assert binding.params["file_path"] == r"C:\Users\analyst\Downloads\invoice_update.exe"
    assert binding.params["declared_missing"] is True


def test_reject_full_sentence_scalar_leakage():
    task, binding = _bind("Triage IOC 185.220.101.45 and explain evidence", "ioc.enrich")
    assert binding.params["ioc"] == "185.220.101.45"
    assert not binding.invalid_fields
