"""Provider runtime status and health policy helpers for CABTA."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


class ProviderHealthService:
    """Own provider normalization, runtime status tracking, and failover policy."""

    def __init__(
        self,
        *,
        primary_provider: str,
        auto_failover: bool,
        fallback_providers: List[str],
        llm_unavailable_cooldown_seconds: float,
        openrouter_force_json_decision_mode: bool,
        model_name_resolver: Callable[[str], str],
        provider_configured_resolver: Callable[[str], bool],
    ):
        self.primary_provider = str(primary_provider or "openrouter").strip().lower() or "openrouter"
        self.auto_failover = bool(auto_failover)
        self.fallback_providers = [
            str(provider).strip().lower()
            for provider in (fallback_providers or [])
            if str(provider).strip()
        ]
        self.llm_unavailable_cooldown_seconds = float(llm_unavailable_cooldown_seconds or 0.0)
        self.openrouter_force_json_decision_mode = bool(openrouter_force_json_decision_mode)
        self.model_name_resolver = model_name_resolver
        self.provider_configured_resolver = provider_configured_resolver
        self.provider_runtime_status: Dict[str, Any] = {
            "provider": self.primary_provider,
            "available": None,
            "status": "unknown",
            "error": None,
            "http_status": None,
            "checked_at": None,
            "last_ready_at": None,
            "consecutive_failures": 0,
            "cooldown_until": None,
        }
        self.provider_runtime_statuses: Dict[str, Dict[str, Any]] = {}

    def normalize_provider(self, provider: Optional[str] = None) -> str:
        return str(provider or self.primary_provider or "openrouter").strip().lower() or "openrouter"

    def record_runtime_status(
        self,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        available: bool,
        error: Optional[str] = None,
        http_status: Optional[int] = None,
    ) -> None:
        provider_name = self.normalize_provider(provider)
        previous = self.provider_runtime_statuses.get(provider_name, {})
        now = datetime.now(timezone.utc)
        previous_failures = int(previous.get("consecutive_failures") or 0)

        consecutive_failures = 0 if available else previous_failures + 1
        last_ready_at = (
            now.isoformat()
            if available
            else (str(previous.get("last_ready_at") or "").strip() or None)
        )
        cooldown_until = None
        if not available and self.llm_unavailable_cooldown_seconds > 0:
            from datetime import timedelta

            cooldown_until = (
                now + timedelta(seconds=self.llm_unavailable_cooldown_seconds)
            ).isoformat()

        status = {
            "provider": provider_name,
            "model": model or self.model_name_resolver(provider_name),
            "available": available,
            "status": "ready" if available else "error",
            "error": error,
            "http_status": http_status,
            "checked_at": now.isoformat(),
            "last_ready_at": last_ready_at,
            "consecutive_failures": consecutive_failures,
            "cooldown_until": None if available else cooldown_until,
        }
        self.provider_runtime_statuses[provider_name] = status
        if provider_name == self.primary_provider:
            self.provider_runtime_status = status

    def runtime_status_for_provider(self, provider: Optional[str] = None) -> Dict[str, Any]:
        provider_name = self.normalize_provider(provider)
        status = self.provider_runtime_statuses.get(provider_name)
        if isinstance(status, dict) and status.get("provider") == provider_name:
            return status
        status = self.provider_runtime_status if isinstance(self.provider_runtime_status, dict) else {}
        if isinstance(status, dict) and self.normalize_provider(status.get("provider")) == provider_name:
            return status
        return {}

    def provider_is_currently_unavailable(self, provider: Optional[str] = None) -> bool:
        status = self.runtime_status_for_provider(provider)
        return bool(status) and status.get("available") is False

    def provider_is_recently_unavailable(self, provider: Optional[str] = None) -> bool:
        if not self.provider_is_currently_unavailable(provider):
            return False

        cooldown_seconds = max(0.0, self.llm_unavailable_cooldown_seconds)
        if cooldown_seconds <= 0:
            return False

        status = self.runtime_status_for_provider(provider)
        checked_at = str(status.get("checked_at") or "").strip()
        if not checked_at:
            return True

        try:
            checked_at_dt = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        except ValueError:
            return True

        if checked_at_dt.tzinfo is None:
            checked_at_dt = checked_at_dt.replace(tzinfo=timezone.utc)

        age_seconds = (datetime.now(timezone.utc) - checked_at_dt).total_seconds()
        return age_seconds <= cooldown_seconds

    def provider_prefers_json_decision_mode(self, provider: Optional[str] = None) -> bool:
        normalized = self.normalize_provider(provider)
        if normalized == "openrouter":
            return self.openrouter_force_json_decision_mode
        return False

    def provider_cooldown_until(self, provider: Optional[str] = None) -> Optional[str]:
        status = self.runtime_status_for_provider(provider)
        value = str(status.get("cooldown_until") or "").strip()
        return value or None

    def provider_failure_count(self, provider: Optional[str] = None) -> int:
        status = self.runtime_status_for_provider(provider)
        return int(status.get("consecutive_failures") or 0)

    def provider_is_in_cooldown(self, provider: Optional[str] = None) -> bool:
        status = self.runtime_status_for_provider(provider)
        cooldown_until = str(status.get("cooldown_until") or "").strip()
        if not cooldown_until:
            return False
        try:
            cooldown_until_dt = datetime.fromisoformat(cooldown_until.replace("Z", "+00:00"))
        except ValueError:
            return True
        if cooldown_until_dt.tzinfo is None:
            cooldown_until_dt = cooldown_until_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) <= cooldown_until_dt

    def candidate_providers(self) -> List[str]:
        configured_candidates = [self.primary_provider]
        if self.normalize_provider(self.primary_provider) == "nvidia":
            return configured_candidates
        if self.auto_failover:
            for provider in self.fallback_providers:
                normalized = self.normalize_provider(provider)
                if normalized in configured_candidates:
                    continue
                if not self.provider_configured_resolver(normalized):
                    continue
                configured_candidates.append(normalized)

        healthy_candidates = [
            provider
            for provider in configured_candidates
            if not self.provider_is_in_cooldown(provider)
        ]
        return healthy_candidates or configured_candidates

    def provider_operational_status(self, provider: Optional[str] = None) -> Dict[str, Any]:
        provider_name = self.normalize_provider(provider)
        runtime_status = dict(self.runtime_status_for_provider(provider_name) or {})
        configured = bool(self.provider_configured_resolver(provider_name))
        in_cooldown = self.provider_is_in_cooldown(provider_name)
        currently_unavailable = self.provider_is_currently_unavailable(provider_name)
        recently_unavailable = self.provider_is_recently_unavailable(provider_name)

        if runtime_status.get("available") is True:
            readiness = "ready"
        elif configured and (currently_unavailable or in_cooldown):
            readiness = "degraded"
        elif configured:
            readiness = "configured"
        else:
            readiness = "not_configured"

        return {
            "provider": provider_name,
            "configured": configured,
            "runtime_checked": bool(runtime_status),
            "ready": runtime_status.get("available") is True,
            "currently_unavailable": currently_unavailable,
            "recently_unavailable": recently_unavailable,
            "in_cooldown": in_cooldown,
            "failure_count": self.provider_failure_count(provider_name),
            "cooldown_until": self.provider_cooldown_until(provider_name),
            "readiness": readiness,
            "status": runtime_status.get("status") or ("configured" if configured else "not_configured"),
            "runtime_status": runtime_status,
        }

    def provider_inventory_statuses(self) -> List[Dict[str, Any]]:
        inventory: List[str] = [self.primary_provider]
        for provider in self.fallback_providers:
            normalized = self.normalize_provider(provider)
            if normalized not in inventory:
                inventory.append(normalized)
        return [self.provider_operational_status(provider) for provider in inventory]
