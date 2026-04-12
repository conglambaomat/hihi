import json

from src.mcp_servers import malwoverview_tools
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
