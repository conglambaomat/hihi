"""Provider-agnostic chat/text request envelope helpers for CABTA LLM providers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class ProviderChatGateway:
    """Build stable provider-facing request envelopes without owning transport."""

    @staticmethod
    def _normalize_provider_name(provider_name: str) -> str:
        return str(provider_name or "").strip().lower()

    @staticmethod
    def _provider_family(provider_name: str) -> str:
        normalized = str(provider_name or "").strip().lower()
        if not normalized:
            return "unknown"
        return normalized.split(":", 1)[0].split("/", 1)[0]

    def _tool_prompting_profile(
        self,
        *,
        provider_family: str,
        mode: str,
        prompt_mode: str,
        structured_intent: str,
        has_tools: bool,
    ) -> Dict[str, Any]:
        if not has_tools or mode != "tool_decision":
            return {
                "tool_prompting_strategy": "disabled",
                "tool_prompting_family": provider_family,
                "tool_decision_format": "none",
                "should_include_tool_schema_in_prompt": False,
            }

        normalized_prompt_mode = str(prompt_mode or structured_intent or "").strip().lower()
        if provider_family == "openrouter":
            return {
                "tool_prompting_strategy": "native_tools",
                "tool_prompting_family": provider_family,
                "tool_decision_format": "native_tool_call",
                "should_include_tool_schema_in_prompt": False,
            }
        if provider_family in {"gemini", "groq", "anthropic", "nvidia", "ollama"}:
            decision_format = "json_tool_decision"
            if normalized_prompt_mode == "native_tooling":
                decision_format = "native_tool_call"
            return {
                "tool_prompting_strategy": "aligned_tool_contract",
                "tool_prompting_family": provider_family,
                "tool_decision_format": decision_format,
                "should_include_tool_schema_in_prompt": decision_format != "native_tool_call",
            }
        return {
            "tool_prompting_strategy": "aligned_tool_contract",
            "tool_prompting_family": provider_family or "unknown",
            "tool_decision_format": "json_tool_decision",
            "should_include_tool_schema_in_prompt": True,
        }

    def build_chat_request(
        self,
        *,
        provider_name: str,
        messages: List[Dict[str, Any]],
        tools_json: Optional[List[Dict[str, Any]]] = None,
        model_only_chat: bool = False,
        prompt_envelope: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized_provider = self._normalize_provider_name(provider_name)
        normalized_messages = [dict(message) for message in (messages or [])]
        normalized_tools = [dict(tool) for tool in (tools_json or [])]
        normalized_prompt_envelope = dict(prompt_envelope or {})
        mode = "direct_answer" if model_only_chat else ("tool_decision" if normalized_tools else "text_generation")
        structured_intent = (
            str(((normalized_prompt_envelope.get("user_intent") or {}).get("mode")) or "").strip()
            if isinstance(normalized_prompt_envelope, dict)
            else ""
        )

        provider_family = self._provider_family(normalized_provider)
        prompt_mode = str(((normalized_prompt_envelope.get("investigation_context") or {}).get("prompt_mode")) or "").strip()
        tool_prompting_profile = self._tool_prompting_profile(
            provider_family=provider_family,
            mode=mode,
            prompt_mode=prompt_mode,
            structured_intent=structured_intent,
            has_tools=bool(normalized_tools) and not model_only_chat,
        )

        request: Dict[str, Any] = {
            "provider": normalized_provider,
            "provider_family": provider_family,
            "messages": normalized_messages,
            "tools": [] if model_only_chat else normalized_tools,
            "mode": mode,
            "intent": mode,
            "tool_choice_allowed": bool(normalized_tools) and not model_only_chat,
            "native_tooling": bool(normalized_tools) and not model_only_chat,
            "prompt_envelope": normalized_prompt_envelope,
            "prompt_mode": prompt_mode,
            "structured_intent": structured_intent,
            **tool_prompting_profile,
        }
        request["message_count"] = len(normalized_messages)
        request["tool_count"] = len(request["tools"])
        return request

    def build_text_request(
        self,
        *,
        provider_name: str,
        prompt: str,
    ) -> Dict[str, Any]:
        normalized_provider = self._normalize_provider_name(provider_name)
        provider_family = self._provider_family(normalized_provider)
        return {
            "provider": normalized_provider,
            "provider_family": provider_family,
            "prompt": str(prompt or ""),
            "mode": "text_generation",
            "intent": "text_generation",
            "native_tooling": False,
            "tool_prompting_strategy": "disabled",
            "tool_prompting_family": provider_family,
            "tool_decision_format": "none",
            "should_include_tool_schema_in_prompt": False,
        }

    @staticmethod
    def extract_chat_messages(request: Dict[str, Any]) -> List[Dict[str, Any]]:
        messages = request.get("messages", [])
        return [dict(message) for message in messages if isinstance(message, dict)]

    @staticmethod
    def extract_chat_tools(request: Dict[str, Any]) -> List[Dict[str, Any]]:
        tools = request.get("tools", [])
        return [dict(tool) for tool in tools if isinstance(tool, dict)]

    @staticmethod
    def extract_text_prompt(request: Dict[str, Any]) -> str:
        return str(request.get("prompt") or "")