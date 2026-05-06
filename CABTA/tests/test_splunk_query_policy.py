import importlib


def test_splunk_safe_query_scopes_bare_sysmon_query_to_allowlist(monkeypatch):
    monkeypatch.setenv("SPLUNK_ALLOWED_INDEXES", "main,soc101")
    monkeypatch.setenv("SPLUNK_DISALLOWED_INDEXES", "_*")
    splunk_tools = importlib.reload(importlib.import_module("src.mcp_servers.splunk_tools"))

    safe = splunk_tools._safe_query('EventCode=1 Image="*wmic.exe"')

    assert safe.startswith("search ")
    assert "index=main OR index=soc101" in safe
    assert "EventCode=1" in safe


def test_splunk_safe_query_blocks_explicit_disallowed_internal_index(monkeypatch):
    monkeypatch.setenv("SPLUNK_ALLOWED_INDEXES", "main,soc101")
    monkeypatch.setenv("SPLUNK_DISALLOWED_INDEXES", "_*")
    splunk_tools = importlib.reload(importlib.import_module("src.mcp_servers.splunk_tools"))

    try:
        splunk_tools._safe_query("search index=_internal error")
    except ValueError as exc:
        assert "disallowed" in str(exc)
    else:
        raise AssertionError("Expected disallowed Splunk index to be blocked")


def test_splunk_safe_query_preserves_explicit_allowed_soc101_index(monkeypatch):
    monkeypatch.setenv("SPLUNK_ALLOWED_INDEXES", "main,soc101")
    monkeypatch.setenv("SPLUNK_DISALLOWED_INDEXES", "_*")
    splunk_tools = importlib.reload(importlib.import_module("src.mcp_servers.splunk_tools"))

    safe = splunk_tools._safe_query("search index=soc101 EventCode=1")

    assert safe == "search index=soc101 EventCode=1"
