import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.provider_health_service import ProviderHealthService


def build_service(**overrides):
    params = {
        "primary_provider": "router",
        "auto_failover": False,
        "fallback_providers": [],
        "llm_unavailable_cooldown_seconds": 30.0,
        "openrouter_force_json_decision_mode": False,
        "model_name_resolver": lambda provider: f"{provider}-model",
        "provider_configured_resolver": lambda provider: provider == "router",
    }
    params.update(overrides)
    return ProviderHealthService(**params)


def test_normalize_provider_returns_router_only():
    service = build_service(primary_provider="router")
    assert service.normalize_provider(None) == "router"
    assert service.normalize_provider(" GROQ ") == "router"
    assert service.normalize_provider("openrouter") == "router"


def test_record_runtime_status_updates_primary_status():
    service = build_service()
    service.record_runtime_status(provider="router", available=False, error="boom", http_status=503)

    status = service.runtime_status_for_provider("router")
    assert status["provider"] == "router"
    assert status["available"] is False
    assert status["http_status"] == 503
    assert status["consecutive_failures"] == 1
    assert status["cooldown_until"] is not None
    assert service.provider_runtime_status["provider"] == "router"


def test_provider_is_recently_unavailable_respects_cooldown():
    service = build_service(llm_unavailable_cooldown_seconds=60.0)
    service.record_runtime_status(provider="router", available=False, error="timeout")
    assert service.provider_is_recently_unavailable("router") is True

    old_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    service.provider_runtime_statuses["router"]["checked_at"] = old_time
    assert service.provider_is_recently_unavailable("router") is False


def test_provider_prefers_json_decision_mode_is_disabled_for_router_contract():
    service = build_service(openrouter_force_json_decision_mode=True)
    assert service.provider_prefers_json_decision_mode("router") is False


def test_candidate_providers_returns_single_router():
    service = build_service(
        primary_provider="router",
        fallback_providers=["groq", "gemini"],
        provider_configured_resolver=lambda provider: provider == "router",
    )

    assert service.candidate_providers() == ["router"]


def test_record_runtime_status_resets_failure_count_after_success():
    service = build_service()
    service.record_runtime_status(provider="router", available=False, error="timeout")
    service.record_runtime_status(provider="router", available=False, error="timeout")

    assert service.provider_failure_count("router") == 2
    assert service.provider_is_in_cooldown("router") is True

    service.record_runtime_status(provider="router", available=True)

    status = service.runtime_status_for_provider("router")
    assert status["available"] is True
    assert status["consecutive_failures"] == 0
    assert status["cooldown_until"] is None
    assert status["last_ready_at"] is not None


def test_provider_operational_status_reports_configured_provider_without_runtime_check():
    service = build_service()

    status = service.provider_operational_status("router")

    assert status["provider"] == "router"
    assert status["configured"] is True
    assert status["runtime_checked"] is True
    assert status["ready"] is False
    assert status["readiness"] == "configured"
    assert status["status"] == "unknown"


def test_provider_operational_status_reports_degraded_when_provider_is_in_cooldown():
    service = build_service()
    service.record_runtime_status(provider="router", available=False, error="timeout", http_status=503)

    status = service.provider_operational_status("router")

    assert status["configured"] is True
    assert status["runtime_checked"] is True
    assert status["currently_unavailable"] is True
    assert status["recently_unavailable"] is True
    assert status["in_cooldown"] is True
    assert status["failure_count"] == 1
    assert status["readiness"] == "degraded"
    assert status["status"] == "error"
    assert status["runtime_status"]["http_status"] == 503


def test_provider_inventory_statuses_returns_single_router_inventory():
    service = build_service(primary_provider="router")
    service.record_runtime_status(provider="router", available=True)

    statuses = service.provider_inventory_statuses()

    assert [item["provider"] for item in statuses] == ["router"]
    assert statuses[0]["readiness"] == "ready"
