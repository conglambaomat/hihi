"""Provider dispatch and failover orchestration for CABTA agent LLM calls."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Dict, List, Optional


class ProviderGateway:
    """Coordinate provider selection, dispatch, failover, and success logging."""

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
        invoke_ollama: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
        invoke_anthropic: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
        invoke_groq: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
        invoke_gemini: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
        invoke_nvidia: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
        invoke_openrouter: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Awaitable[Optional[Any]]],
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

        if normalized == "ollama":
            return await invoke_ollama(request_messages, request_tools)
        if normalized == "anthropic":
            return await invoke_anthropic(request_messages, request_tools)
        if normalized == "groq":
            return await invoke_groq(request_messages, request_tools)
        if normalized == "gemini":
            return await invoke_gemini(request_messages, request_tools)
        if normalized == "nvidia":
            return await invoke_nvidia(request_messages, request_tools)
        if normalized == "openrouter":
            return await invoke_openrouter(request_messages, request_tools)
        logger.error("[AGENT] Unsupported provider configured: %s", normalized)
        return None

    @staticmethod
    async def dispatch_text_provider(
        *,
        provider_name: str,
        request: Dict[str, Any],
        extract_text_prompt: Callable[[Dict[str, Any]], str],
        invoke_ollama: Callable[[str], Awaitable[Optional[str]]],
        invoke_anthropic: Callable[[str], Awaitable[Optional[str]]],
        invoke_groq: Callable[[str], Awaitable[Optional[str]]],
        invoke_gemini: Callable[[str], Awaitable[Optional[str]]],
        invoke_nvidia: Callable[[str], Awaitable[Optional[str]]],
        invoke_openrouter: Callable[[str], Awaitable[Optional[str]]],
        logger,
        normalize_provider: Optional[Callable[[Optional[str]], str]] = None,
    ) -> Optional[str]:
        normalized = (
            normalize_provider(provider_name)
            if normalize_provider is not None
            else str(provider_name or "").strip().lower()
        )
        request_prompt = extract_text_prompt(request)

        if normalized == "ollama":
            return await invoke_ollama(request_prompt)
        if normalized == "anthropic":
            return await invoke_anthropic(request_prompt)
        if normalized == "groq":
            return await invoke_groq(request_prompt)
        if normalized == "gemini":
            return await invoke_gemini(request_prompt)
        if normalized == "nvidia":
            return await invoke_nvidia(request_prompt)
        if normalized == "openrouter":
            return await invoke_openrouter(request_prompt)
        logger.error("[AGENT] Unsupported provider configured: %s", normalized)
        return None

    async def _with_failover(
        self,
        *,
        invoke: Callable[[str], Awaitable[Optional[Any]]],
        success_log_template: str,
        failure_log_template: str,
    ) -> Optional[Any]:
        candidates = self._candidate_providers()
        primary = self._primary_provider()

        for provider_name in candidates:
            try:
                response = await invoke(provider_name)
            except Exception as exc:
                self._logger.info(
                    "[AGENT] Provider %s failed during failover attempt: %s",
                    provider_name,
                    exc,
                )
                continue
            if response is not None:
                if provider_name != primary:
                    self._logger.info(
                        success_log_template,
                        provider_name,
                        primary,
                    )
                return response

        self._logger.error(failure_log_template, ", ".join(candidates))
        return None

    async def chat_with_failover(
        self,
        *,
        invoke_provider_chat: Callable[..., Awaitable[Optional[Any]]],
        messages: list[dict],
        tools_payload: list[dict],
        request_metadata: Optional[dict] = None,
    ) -> Optional[Any]:
        async def _invoke(provider_name: str) -> Optional[Any]:
            if request_metadata is not None:
                try:
                    return await invoke_provider_chat(provider_name, messages, tools_payload, request_metadata)
                except TypeError:
                    signature = inspect.signature(invoke_provider_chat)
                    if len(signature.parameters) != 4:
                        return await invoke_provider_chat(provider_name, messages, tools_payload)
                    raise
            return await invoke_provider_chat(provider_name, messages, tools_payload)

        return await self._with_failover(
            invoke=_invoke,
            success_log_template="[AGENT] Chat tool-call failover succeeded via %s after %s was unavailable.",
            failure_log_template="[AGENT] All configured chat providers failed: %s",
        )

    async def text_with_failover(
        self,
        *,
        invoke_provider_text: Callable[[str, str], Awaitable[Optional[str]]],
        prompt: str,
    ) -> Optional[str]:
        return await self._with_failover(
            invoke=lambda provider_name: invoke_provider_text(provider_name, prompt),
            success_log_template="[AGENT] Text generation failover succeeded via %s after %s was unavailable.",
            failure_log_template="[AGENT] All configured text-generation providers failed: %s",
        )
