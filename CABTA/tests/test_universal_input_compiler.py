from src.agent.capability_plan import CapabilityPlanBuilder
from src.agent.soc_task_state import SOCTaskState
from src.agent.universal_input_compiler import UniversalInputCompiler


SPLUNK_STREAM_LOG = 'host=splunk-02 source=stream:tcp sourcetype=stream:tcp src_ip=192.168.250.100 dest_ip=192.168.250.40 dest_port=8089 protocol=tcp ssl_subject_common_name=SplunkServerDefaultCert'


def test_compiles_pasted_splunk_stream_tcp_as_raw_log_artifact():
    compiler = UniversalInputCompiler()
    compiled = compiler.compile(SPLUNK_STREAM_LOG, {})

    assert compiled.input_kind == "raw_log_artifact"
    assert compiled.artifact_type == "splunk_stream_tcp"
    assert compiled.lane == "network_log_hunt"
    assert "splunk" in compiled.requested_backends
    assert any(entity["role"] == "source_ip" for entity in compiled.entities)
    assert compiled.parser["parsed_fields"]["destination_port"] == "8089"


def test_compiler_applies_objective_contract_and_raw_log_capability_plan():
    task = SOCTaskState(raw_request=SPLUNK_STREAM_LOG, session_id="s1")
    compiler = UniversalInputCompiler()
    compiled = compiler.compile(SPLUNK_STREAM_LOG, {})
    task = compiler.apply_to_task_state(task, compiled)
    plan = CapabilityPlanBuilder().build(task, task.objective_contract)

    assert task.compiled_input["compiled_input_id"] == compiled.compiled_input_id
    assert task.objective_contract["compiled_input_ref"] == compiled.compiled_input_id
    assert task.objective_contract["coverage_lane"] == "network_log_hunt"
    assert task.required_capabilities[0] == "log.analyze.inline"
    assert plan.actions[0]["capability_id"] == "log.analyze.inline"
    assert "email.parse.inline" in plan.actions[0]["forbidden_fallbacks"]


def test_compiles_natural_log_hunt_as_log_search_not_ioc():
    compiled = UniversalInputCompiler().compile("Search Splunk for failed logons in the last 24h", {})

    assert compiled.input_kind == "natural_request"
    assert compiled.lane == "network_log_hunt"
    assert compiled.requested_timerange["effective"].lower() == "24h"


def test_compiles_historical_sysmon_artifact_timerange_from_ts_utc():
    raw = " ".join([
        "ts_utc=2025-01-11T09:21:50Z",
        "_time=2026-02-13T19:36:16+07:00",
        "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "EventID=1 Computer=WIN-1 User=ACME\\alice",
        "Image=C:\\Windows\\System32\\cmd.exe",
        "ParentImage=C:\\Windows\\explorer.exe",
        "CommandLine=cmd.exe /c whoami",
    ])

    compiled = UniversalInputCompiler().compile(raw, {})

    assert compiled.input_kind == "raw_log_artifact"
    assert compiled.parser["parsed_fields"]["timestamp"] == "2025-01-11T09:21:50Z"
    assert compiled.requested_timerange["source"] == "artifact_timestamp"
    assert compiled.requested_timerange["effective"].startswith("2025-01-11T08:51:50Z..2025-01-11T11:21:50Z")
    assert compiled.requested_timerange["effective"] != "24h"


def test_raw_artifact_without_timestamp_falls_back_to_24h():
    compiled = UniversalInputCompiler().compile(SPLUNK_STREAM_LOG, {})

    assert compiled.requested_timerange["source"] == "default"
    assert compiled.requested_timerange["effective"] == "24h"
