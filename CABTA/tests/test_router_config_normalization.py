from src.utils.config import enforce_router_only


def test_enforce_router_only_preserves_router_endpoint_model_and_key_aliases():
    config = {
        "api_keys": {"openrouter": "legacy-key"},
        "llm": {
            "provider": "openrouter",
            "base_url": "https://router.example/v1/",
            "model": "cx/custom",
        },
    }

    normalized = enforce_router_only(config)

    assert normalized["llm"]["provider"] == "router"
    assert normalized["llm"]["base_url"] == "https://router.example/v1"
    assert normalized["llm"]["model"] == "cx/custom"
    assert normalized["llm"]["api_key"] == "legacy-key"
    assert normalized["api_keys"]["router"] == "legacy-key"


def test_enforce_router_only_drops_legacy_runtime_semantics():
    config = {
        "api_keys": {"router": "router-key"},
        "llm": {
            "provider": "groq",
            "fallback_providers": ["gemini"],
            "auto_failover": True,
            "openrouter_force_json_decision_mode": True,
        },
    }

    normalized = enforce_router_only(config)

    assert normalized["llm"] == {
        "provider": "router",
        "base_url": "http://localhost:20128/v1",
        "model": "cx/gpt-5.4",
        "api_key": "router-key",
    }
