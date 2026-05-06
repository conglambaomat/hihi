"""Router-only dispatch helpers for AISA agent LLM calls."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Dict, List, Optional


class ProviderGatewayError(RuntimeError):
    """Raised when the canonical LLM router cannot satisfy a request."""


class ProviderGateway:
    """Dispatch agent requests through the single canonical router provider."""

    def __init__(
        self,
        *,
        candidate_providers: Callable[[], List[str]],
        primary_provider: Callable[[], str],
        logger,
    ):
        self._candidate_providers = candidate_providers
        self._primary_provider = primary_provider
        self._logger = logger

    @staticmethod
    async def dispatch_chat_provider(
        *,
        provider_name: str,
        request: Dict[str, Any],
        extract_chat_messages: Callable[[Dict[str, Any]], List[Dict[str, Any]]],
        extract_chat_tools: Callable[[Dict[str, Any]], List[Dict[str, Any]]],
        invoke_router: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
        logger,
        normalize_provider: Optional[Callable[[Optional[str]], str]] = None,
    ) -> Optional[Any]:
        normalized = (
            normalize_provider(provider_name)
            if normalize_provider is not None
            else str(provider_name or "").strip().lower()
        )
        request_messages = extract_chat_messages(request)
        request_tools = extract_chat_tools(request)

        if normalized == "router":
            return await invoke_router(request_messages, request_tools)
        raise ProviderGatewayError(f"Unsupported provider configured: {normalized or '<empty>'}")

    @staticmethod
    async def dispatch_text_provider(
        *,
        provider_name: str,
        request: Dict[str, Any],
        extract_text_prompt: Callable[[Dict[str, Any]], str],
        invoke_router: Callable[[str], Awaitable[Optional[str]]],
        logger,
        normalize_provider: Optional[Callable[[Optional[str]], str]] = None,
    ) -> Optional[str]:
        normalized = (
            normalize_provider(provider_name)
            if normalize_provider is not None
            else str(provider_name or "").strip().lower()
        )
        request_prompt = extract_text_prompt(request)

        if normalized == "router":
            return await invoke_router(request_prompt)
        raise ProviderGatewayError(f"Unsupported provider configured: {normalized or '<empty>'}")

    async def chat(
        self,
        *,
        invoke_provider_chat: Callable[..., Awaitable[Optional[Any]]],
        messages: list[dict],
        tools_payload: list[dict],
        request_metadata: Optional[dict] = None,
    ) -> Optional[Any]:
        provider_name = self._primary_provider()
        try:
            if request_metadata is not None:
                try:
                    return await invoke_provider_chat(provider_name, messages, tools_payload, request_metadata)
                except TypeError:
                    signature = inspect.signature(invoke_provider_chat)
                    if len(signature.parameters) != 4:
                        return await invoke_provider_chat(provider_name, messages, tools_payload)
                    raise
            return await invoke_provider_chat(provider_name, messages, tools_payload)
        except Exception as exc:
            error_detail = str(exc).strip() or type(exc).__name__
            self._logger.error("[AGENT] Router chat request failed: %s", error_detail)
            raise ProviderGatewayError(f"Router chat request failed: {error_detail}") from exc

    async def text(
        self,
        *,
        invoke_provider_text: Callable[[str, str], Awaitable[Optional[str]]],
        prompt: str,
    ) -> Optional[str]:
        provider_name = self._primary_provider()
        try:
            return await invoke_provider_text(provider_name, prompt)
        except Exception as exc:
            error_detail = str(exc).strip() or type(exc).__name__
            self._logger.error("[AGENT] Router text request failed: %s", error_detail)
            raise ProviderGatewayError(f"Router text request failed: {error_detail}") from exc
