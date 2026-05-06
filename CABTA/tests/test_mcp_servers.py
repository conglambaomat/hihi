import json

from src.mcp_servers import malwoverview_tools
from src.mcp_servers import splunk_tools
from src.mcp_servers import threat_intel_tools


def test_threat_intel_threatfox_requires_auth_without_key(monkeypatch):
    monkeypatch.setattr(threat_intel_tools, "THREATFOX_AUTH_KEY", "")

    result = json.loads(threat_intel_tools.threatfox_ioc_lookup("example.com"))

    assert result["query_status"] == "auth_required"
    assert result["source"] == "ThreatFox"
    assert result["manual"] is True
    assert result["found"] is False


def test_threat_intel_urlhaus_requires_auth_without_key(monkeypatch):
    monkeypatch.setattr(threat_intel_tools, "URLHAUS_AUTH_KEY", "")

    result = json.loads(threat_intel_tools.urlhaus_lookup("example.com"))

    assert result["query_status"] == "auth_required"
    assert result["source"] == "URLhaus"
    assert result["manual"] is True
    assert result["found"] is False


def test_malwoverview_threatfox_query_requires_auth_without_key(monkeypatch):
    monkeypatch.setattr(malwoverview_tools, "THREATFOX_AUTH_KEY", "")

    result = malwoverview_tools._query_threatfox_ioc("example.com")

    assert result["query_status"] == "auth_required"
    assert result["source"] == "ThreatFox"
    assert result["manual"] is True
    assert result["found"] is False


def test_malwoverview_urlhaus_query_requires_auth_without_key(monkeypatch):
    monkeypatch.setattr(malwoverview_tools, "URLHAUS_AUTH_KEY", "")

    result = malwoverview_tools._query_urlhaus_host("example.com")

    assert result["query_status"] == "auth_required"
    assert result["source"] == "URLhaus"
    assert result["manual"] is True
    assert result["found"] is False


def test_malwoverview_domain_check_preserves_auth_required_state(monkeypatch):
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_urlhaus_host",
        lambda domain: {"query_status": "no_results"},
    )
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_threatfox_ioc",
        lambda domain: {
            "query_status": "auth_required",
            "source": "ThreatFox",
            "found": False,
            "manual": True,
            "message": "auth required",
        },
    )
    monkeypatch.setattr(
        malwoverview_tools,
        "_run_malwoverview",
        lambda *args, **kwargs: {"error": "not installed"},
    )

    result = json.loads(malwoverview_tools.malwoverview_domain_check("example.com"))

    assert result["sources"]["threatfox"]["query_status"] == "auth_required"
    assert result["sources"]["threatfox"]["manual"] is True
    assert result["sources"]["urlhaus"]["found"] is False
    assert result["verdict"].startswith("PARTIAL")


def test_splunk_search_logs_blocks_mutating_queries():
    result = splunk_tools.search_logs("index=* | outputlookup suspicious.csv", timerange="24h")

    assert result["status"] == "blocked"
    assert result["backend"] == "splunk"


def test_splunk_search_logs_executes_with_mocked_backend(monkeypatch):
    monkeypatch.setattr(splunk_tools, "SPLUNK_URL", "https://splunk.example.local:8089")
    monkeypatch.setattr(splunk_tools, "SPLUNK_TOKEN", "token")
    sent_searches = []

    def fake_request(path, method="GET", data=None):
        if path == "/services/search/jobs" and method == "POST":
            sent_searches.append(data["search"])
            return {"sid": "job123"}
        if path == "/services/search/jobs/job123" and method == "GET":
            return {"entry": [{"content": {"isDone": "1", "dispatchState": "DONE"}}]}
        if path == "/services/search/jobs/job123/results" and method == "GET":
            return {"results": [{"dest_ip": "1.2.3.4", "process_name": "cmd.exe"}]}
        if path == "/services/search/jobs/job123" and method == "POST":
            return {"status": "ok"}
        raise AssertionError(f"Unexpected Splunk request: {method} {path} {data}")

    monkeypatch.setattr(splunk_tools, "_request", fake_request)

    result = splunk_tools.search_logs(
        'index=network | search dest_ip="1.2.3.4"',
        timerange="24h",
        max_results=10,
    )

    assert result["status"] == "executed"
    assert result["results_count"] == 1
    assert result["query"] == 'search index=network | search dest_ip="1.2.3.4"'
    assert sent_searches == ['search index=network | search dest_ip="1.2.3.4"']
    assert "1.2.3.4" in result["suspicious_indicators"]



def test_splunk_timerange_normalizes_lowercase_iso_before_dispatch(monkeypatch):
    monkeypatch.setattr(splunk_tools, "SPLUNK_URL", "https://splunk.example.local:8089")
    monkeypatch.setattr(splunk_tools, "SPLUNK_TOKEN", "token")
    sent = []

    def fake_request(path, method="GET", data=None):
        sent.append((path, data or {}))
        if path == "/services/search/jobs":
            return {"sid": "sid-iso"}
        if path.endswith("/results"):
            return {"results": []}
        return {"entry": [{"content": {"isDone": "1"}}]}

    monkeypatch.setattr(splunk_tools, "_request", fake_request)

    result = splunk_tools.search_logs("search index=win EventCode=1002 | head 1", timerange="2016-08-24t12:17:43..2016-08-24t12:37:43")

    create_payload = sent[0][1]
    assert result["timerange"] == "2016-08-24T12:17:43..2016-08-24T12:37:43"
    assert create_payload["earliest_time"] == "2016-08-24T12:17:43"
    assert create_payload["latest_time"] == "2016-08-24T12:37:43"


def test_splunk_dispatch_failure_marks_collection_failed(monkeypatch):
    monkeypatch.setattr(splunk_tools, "SPLUNK_URL", "https://splunk.example.local:8089")
    monkeypatch.setattr(splunk_tools, "SPLUNK_TOKEN", "token")
    monkeypatch.setattr(splunk_tools, "_request", lambda *_, **__: {"status": "error", "error": "Invalid earliest_time"})

    result = splunk_tools.search_logs("search index=win EventCode=1002 | head 1", timerange="2016-08-24t12:17:43..2016-08-24t12:37:43")

    assert result["status"] == "error"
    assert result["collection_status"] == "collection_failed"


def test_splunk_probe_source_binding_uses_discovered_profile(monkeypatch):
    monkeypatch.setattr(splunk_tools, "discover_sources", lambda **_: {"status": "executed", "source_profile": {"indexes": ["win"], "sourcetypes": ["XmlWinEventLog:Sysmon"]}})

    result = splunk_tools.probe_source_binding('EventCode=1002 "Get-WmiObject" | head 10')

    assert "index=win" in result["query"]
    assert "XmlWinEventLog:Sysmon" in result["query"]


def test_splunk_safe_query_prefixes_raw_search_expressions(monkeypatch):
    monkeypatch.setattr(splunk_tools, "SPLUNK_ALLOWED_INDEXES", [])

    assert splunk_tools._safe_query("index=main | head 1") == "search index=main | head 1"
    assert splunk_tools._safe_query('sourcetype=wineventlog EventCode=4625 | head 1') == "search sourcetype=wineventlog EventCode=4625 | head 1"
    assert splunk_tools._safe_query('"185.220.101.45" OR sha256=abcd | head 1') == 'search "185.220.101.45" OR sha256=abcd | head 1'



def test_splunk_safe_query_does_not_double_prefix_generating_commands(monkeypatch):
    monkeypatch.setattr(splunk_tools, "SPLUNK_ALLOWED_INDEXES", [])

    assert splunk_tools._safe_query("search index=main | head 1") == "search index=main | head 1"
    assert splunk_tools._safe_query("| makeresults") == "| makeresults"
    assert splunk_tools._safe_query("| eventcount summarize=false index=*") == "| eventcount summarize=false index=*"
    assert splunk_tools._safe_query("tstats count where index=main by host") == "tstats count where index=main by host"



def test_splunk_safe_query_allowed_index_injection_stays_valid(monkeypatch):
    monkeypatch.setattr(splunk_tools, "SPLUNK_ALLOWED_INDEXES", ["main"])

    assert splunk_tools._safe_query('host="ws-12" | head 1') == 'search (index=main) (host="ws-12" | head 1)'
