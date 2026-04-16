from src.utils.api_key_validator import is_valid_api_key
from src.integrations.sandbox_integration import SandboxIntegration


def test_api_key_validator_rejects_known_placeholder_live_tokens():
    assert is_valid_api_key("vt-live-12345678") is False
    assert is_valid_api_key("gsk-live-12345678") is False
    assert is_valid_api_key("sk-live-12345678") is False


def test_sandbox_integration_treats_placeholder_virustotal_key_as_unconfigured():
    integration = SandboxIntegration(config={"api_keys": {"virustotal": "vt-live-12345678"}})

    assert integration._get_api_key("virustotal") == ""
