import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.provider_health_service import ProviderHealthService


def build_service(**overrides):
    params = {
        "primary_provider": "openrouter",
        "auto_failover": True,
        "fallback_providers": ["groq", "gemini", "nvidia"],
        "llm_unavailable_cooldown_seconds": 30.0,
        "openrouter_force_json_decision_mode": True,
        "model_name_resolver": lambda provider: f"{provider}-model",
        "provider_configured_resolver": lambda provider: provider in {"openrouter", "groq", "gemini"},
    }
    params.update(overrides)
    return ProviderHealthService(**params)


def test_normalize_provider_defaults_to_primary():
    service = build_service(primary_provider="OpenRouter")
    assert service.normalize_provider(None) == "openrouter"
    assert service.normalize_provider(" GROQ ") == "groq"


def test_record_runtime_status_updates_primary_status():
    service = build_service()
    service.record_runtime_status(provider="openrouter", available=False, error="boom", http_status=503)

    status = service.runtime_status_for_provider("openrouter")
    assert status["provider"] == "openrouter"
    assert status["available"] is False
    assert status["http_status"] == 503
    assert status["consecutive_failures"] == 1
    assert status["cooldown_until"] is not None
    assert service.provider_runtime_status["provider"] == "openrouter"


def test_provider_is_recently_unavailable_respects_cooldown():
    service = build_service(llm_unavailable_cooldown_seconds=60.0)
    service.record_runtime_status(provider="openrouter", available=False, error="timeout")
    assert service.provider_is_recently_unavailable("openrouter") is True

    old_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    service.provider_runtime_statuses["openrouter"]["checked_at"] = old_time
    assert service.provider_is_recently_unavailable("openrouter") is False


def test_provider_prefers_json_decision_mode_for_openrouter_only():
    service = build_service(openrouter_force_json_decision_mode=True)
    assert service.provider_prefers_json_decision_mode("openrouter") is True
    assert service.provider_prefers_json_decision_mode("groq") is False


def test_candidate_providers_filters_unconfigured_fallbacks():
    service = build_service(
        primary_provider="openrouter",
        fallback_providers=["groq", "gemini", "nvidia"],
        provider_configured_resolver=lambda provider: provider in {"openrouter", "groq"},
    )

    assert service.candidate_providers() == ["openrouter", "groq"]


def test_record_runtime_status_resets_failure_count_after_success():
    service = build_service()
    service.record_runtime_status(provider="openrouter", available=False, error="timeout")
    service.record_runtime_status(provider="openrouter", available=False, error="timeout")

    assert service.provider_failure_count("openrouter") == 2
    assert service.provider_is_in_cooldown("openrouter") is True

    service.record_runtime_status(provider="openrouter", available=True)

    status = service.runtime_status_for_provider("openrouter")
    assert status["available"] is True
    assert status["consecutive_failures"] == 0
    assert status["cooldown_until"] is None
    assert status["last_ready_at"] is not None


def test_candidate_providers_skips_providers_in_cooldown_when_healthy_alternatives_exist():
    service = build_service(
        primary_provider="openrouter",
        fallback_providers=["groq", "gemini"],
        provider_configured_resolver=lambda provider: provider in {"openrouter", "groq", "gemini"},
    )
    service.record_runtime_status(provider="openrouter", available=False, error="timeout")

    candidates = service.candidate_providers()

    assert "openrouter" not in candidates
    assert candidates == ["groq", "gemini"]


def test_candidate_providers_falls_back_to_configured_list_when_all_are_in_cooldown():
    service = build_service(
        primary_provider="openrouter",
        fallback_providers=["groq"],
        provider_configured_resolver=lambda provider: provider in {"openrouter", "groq"},
    )
    service.record_runtime_status(provider="openrouter", available=False, error="timeout")
    service.record_runtime_status(provider="groq", available=False, error="timeout")

    assert service.candidate_providers() == ["openrouter", "groq"]


def test_candidate_providers_disables_failover_for_nvidia_primary():
    service = build_service(primary_provider="nvidia")
    assert service.candidate_providers() == ["nvidia"]


def test_provider_operational_status_reports_configured_provider_without_runtime_check():
    service = build_service()

    status = service.provider_operational_status("groq")

    assert status["provider"] == "groq"
    assert status["configured"] is True
    assert status["runtime_checked"] is False
    assert status["ready"] is False
    assert status["readiness"] == "configured"
    assert status["status"] == "configured"


def test_provider_operational_status_reports_degraded_when_provider_is_in_cooldown():
    service = build_service()
    service.record_runtime_status(provider="openrouter", available=False, error="timeout", http_status=503)

    status = service.provider_operational_status("openrouter")

    assert status["configured"] is True
    assert status["runtime_checked"] is True
    assert status["currently_unavailable"] is True
    assert status["recently_unavailable"] is True
    assert status["in_cooldown"] is True
    assert status["failure_count"] == 1
    assert status["readiness"] == "degraded"
    assert status["status"] == "error"
    assert status["runtime_status"]["http_status"] == 503


def test_provider_inventory_statuses_returns_unique_inventory_with_runtime_truth():
    service = build_service(
        primary_provider="openrouter",
        fallback_providers=["groq", "gemini", "groq"],
    )
    service.record_runtime_status(provider="openrouter", available=True)
    service.record_runtime_status(provider="gemini", available=False, error="rate_limited")

    statuses = service.provider_inventory_statuses()

    assert [item["provider"] for item in statuses] == ["openrouter", "groq", "gemini"]
    assert statuses[0]["readiness"] == "ready"
    assert statuses[1]["readiness"] == "configured"
    assert statuses[2]["readiness"] == "degraded"
