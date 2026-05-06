from src.agent.raw_log_parser import RawLogParser, analyze_log_artifact


SPLUNK_STREAM_LOG = 'host=splunk-02 source=stream:tcp sourcetype=stream:tcp src_ip=192.168.250.100 dest_ip=192.168.250.40 dest_port=8089 protocol=tcp ssl_subject_common_name=SplunkServerDefaultCert'
FORTIGATE_LOG = 'date=2026-04-29 time=12:00:01 devname=fw01 srcip=10.0.0.10 dstip=8.8.8.8 dstport=53 proto=udp action=accept service=DNS'
SYSMON_SPLUNK_LOG = (
    'index=wineventlog sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational '
    'Computer=HR-WIN-001 EventID=1 UtcTime=2026-04-29T08:12:30Z '
    'User=ACME\\trang.nguyen Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
    'ParentImage="C:\\Users\\Public\\stage2.exe" '
    'CommandLine="powershell.exe -NoProfile Get-WmiObject -Class Win32_Bios" '
    'SourceIp=10.10.20.15 Hashes="SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
)


def test_parse_splunk_key_value_stream_tcp_fields():
    result = RawLogParser().parse(SPLUNK_STREAM_LOG)
    fields = result.best_fields

    assert result.artifact_type == "splunk_stream_tcp"
    assert fields["source_ip"] == "192.168.250.100"
    assert fields["destination_ip"] == "192.168.250.40"
    assert fields["destination_port"] == "8089"
    assert fields["host"] == "splunk-02"
    assert fields["certificate"] == "SplunkServerDefaultCert"
    assert "sender" not in fields
    assert "recipient" not in fields


def test_parse_fortigate_key_value_fields():
    fields = RawLogParser().parse(FORTIGATE_LOG).best_fields

    assert fields["host"] == "fw01"
    assert fields["source_ip"] == "10.0.0.10"
    assert fields["destination_ip"] == "8.8.8.8"
    assert fields["destination_port"] == "53"
    assert fields["action"] == "accept"


def test_parse_sysmon_splunk_event_preserves_endpoint_fields():
    result = analyze_log_artifact(raw_log_text=SYSMON_SPLUNK_LOG, compiled_input_ref="ci-sysmon")
    fields = result["parsed_fields"]

    assert result["artifact_type"] == "sysmon_log_event"
    assert fields["host"] == "HR-WIN-001"
    assert fields["process"].endswith("powershell.exe")
    assert fields["parent_process"].endswith("stage2.exe")
    assert fields["user"] == "ACME\\trang.nguyen"
    assert "Get-WmiObject" in fields["command_line"]
    assert fields["hash"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert fields["timestamp"] == "2026-04-29T08:12:30Z"
    assert fields["source_ip"] == "10.10.20.15"
    assert {"host", "process", "parent_process", "user", "command_line", "hash"}.issubset(result["coverage"]["covered_facets"])


def test_parse_json_log_event_fields():
    raw = '{"@timestamp":"2026-04-29T12:00:00Z","src":"10.1.1.5","dst":"10.1.1.20","dest_port":443,"protocol":"tcp","action":"allow"}'
    fields = RawLogParser().parse(raw).best_fields

    assert fields["timestamp"] == "2026-04-29T12:00:00Z"
    assert fields["source_ip"] == "10.1.1.5"
    assert fields["destination_ip"] == "10.1.1.20"
    assert fields["protocol_app"] == "tcp"


def test_analyze_log_artifact_structured_verdict_inconclusive_for_single_event():
    result = analyze_log_artifact(raw_log_text=SPLUNK_STREAM_LOG, compiled_input_ref="ci-test")

    assert result["schema_version"] == "log-artifact-analysis-result/v1"
    assert result["structured_verdict"]["verdict"] == "inconclusive"
    assert result["structured_verdict"]["ui_badge"] == "inconclusive"
    assert any("malicious" in item["claim"] for item in result["structured_verdict"]["unsupported_claims"])
    assert "email.parse.inline" not in str(result)
