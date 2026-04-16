import asyncio

import pytest
from unittest.mock import AsyncMock

from src.integrations.threat_intel import ThreatIntelligence


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, requests, payload, *args, **kwargs):
        self._requests = requests
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, url, headers=None):
        self._requests.append((url, headers))
        return _FakeResponse(self._payload, status=200)


@pytest.mark.parametrize("ioc_type", ["hash", "md5", "sha1", "sha256"])
def test_check_virustotal_treats_all_hash_types_as_file_lookups(monkeypatch, ioc_type):
    requests = []
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 67,
                    "harmless": 9,
                    "suspicious": 0,
                    "undetected": 0,
                },
                "last_analysis_date": 1713225600,
            }
        }
    }

    monkeypatch.setattr(
        "src.integrations.threat_intel.get_valid_key",
        lambda api_keys, key_name: "test-key",
    )
    monkeypatch.setattr(
        "src.integrations.threat_intel.aiohttp.ClientSession",
        lambda *args, **kwargs: _FakeSession(requests, payload, *args, **kwargs),
    )

    client = ThreatIntelligence({"api_keys": {"virustotal": "test-key"}})
    result = asyncio.run(client.check_virustotal("deadbeef", ioc_type))

    assert requests == [
        ("https://www.virustotal.com/api/v3/files/deadbeef", {"x-apikey": "test-key"})
    ]
    assert result["status"] == "✓"
    assert result["detections"] == "67/76"
    assert result["score"] == 100


def test_check_virustotal_rejects_unknown_types_without_network(monkeypatch):
    requests = []

    monkeypatch.setattr(
        "src.integrations.threat_intel.get_valid_key",
        lambda api_keys, key_name: "test-key",
    )
    monkeypatch.setattr(
        "src.integrations.threat_intel.aiohttp.ClientSession",
        lambda *args, **kwargs: _FakeSession(requests, {}, *args, **kwargs),
    )

    client = ThreatIntelligence({"api_keys": {"virustotal": "test-key"}})
    result = asyncio.run(client.check_virustotal("deadbeef", "email"))

    assert result == {"status": "⚠", "error": "Unsupported type"}
    assert requests == []


def test_check_threatfox_requires_auth_without_network(monkeypatch):
    requests = []

    def _unexpected_session(*args, **kwargs):
        requests.append((args, kwargs))
        raise AssertionError("ThreatFox should not open a network session without an auth key")

    monkeypatch.setattr(
        "src.integrations.threat_intel.get_valid_key",
        lambda api_keys, key_name: "",
    )
    monkeypatch.setattr(
        "src.integrations.threat_intel.aiohttp.ClientSession",
        _unexpected_session,
    )

    client = ThreatIntelligence({"api_keys": {"threatfox": "", "abusech": ""}})
    result = asyncio.run(client.check_threatfox("example.com"))

    assert result["query_status"] == "auth_required"
    assert result["source"] == "ThreatFox"
    assert result["manual"] is True
    assert requests == []


@pytest.mark.asyncio
async def test_investigate_ioc_uses_per_source_timeout_for_threatfox(mock_config):
    mock_config["api_keys"]["threatfox"] = "test-threatfox-key"
    mock_config.setdefault("timeouts", {})["source_timeouts"] = {"threatfox": 0.1}

    client = ThreatIntelligence(mock_config)
    progress = []
    client.set_progress_callback(lambda source, status: progress.append((source, status)))

    client.check_virustotal = AsyncMock(return_value={"status": "✗", "score": 0})
    client.check_alienvault = AsyncMock(return_value={"status": "✗", "score": 0})
    client.check_malwarebazaar = AsyncMock(return_value={"status": "✗", "score": 0})
    client.extended.check_triage = AsyncMock(return_value={"status": "✗", "score": 0})
    client.extended.check_threatzone = AsyncMock(return_value={"status": "✗", "score": 0})

    async def _slow_threatfox(_ioc):
        await asyncio.sleep(0.2)
        return {"status": "✓", "score": 90}

    client.check_threatfox = _slow_threatfox

    result = await client.investigate_ioc_comprehensive("deadbeef", "hash")

    assert result["sources"]["threatfox"]["error"] == "Timeout"
    assert any(source == "threatfox" and "timeout" in status for source, status in progress)
