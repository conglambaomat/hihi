"""Router-only chat/text request envelope helpers for AISA LLM runtime."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class ProviderChatGateway:
    """Build stable router-facing request envelopes without owning transport."""

    @staticmethod
    def _normalize_provider_name(provider_name: str) -> str:
        normalized = str(provider_name or "").strip().lower()
        return normalized or "router"

    def _tool_prompting_profile(
        self,
        *,
        mode: str,
        has_tools: bool,
    ) -> Dict[str, Any]:
        if not has_tools or mode != "tool_decision":
            return {
                "tool_prompting_strategy": "disabled",
                "tool_prompting_family": "router",
                "tool_decision_format": "none",
                "should_include_tool_schema_in_prompt": False,
            }

        return {
            "tool_prompting_strategy": "native_tools",
            "tool_prompting_family": "router",
            "tool_decision_format": "native_tool_call",
            "should_include_tool_schema_in_prompt": False,
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

        prompt_mode = str(((normalized_prompt_envelope.get("investigation_context") or {}).get("prompt_mode")) or "").strip()
        tool_prompting_profile = self._tool_prompting_profile(
            mode=mode,
            has_tools=bool(normalized_tools) and not model_only_chat,
        )

        request: Dict[str, Any] = {
            "provider": "router",
            "provider_family": "router",
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

    def build_interpretation_request(
        self,
        *,
        provider_name: str,
        messages: List[Dict[str, Any]],
        prompt_envelope: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized_messages = [dict(message) for message in (messages or [])]
        return {
            "provider": "router",
            "provider_family": "router",
            "messages": normalized_messages,
            "tools": [],
            "mode": "schema_interpretation",
            "intent": "soc_request_interpretation",
            "tool_choice_allowed": False,
            "native_tooling": False,
            "response_format": {"type": "json_object"},
            "prompt_envelope": dict(prompt_envelope or {}),
            "prompt_mode": "schema_interpretation",
            "structured_intent": "soc_request_interpretation",
            "tool_prompting_strategy": "disabled",
            "tool_prompting_family": "router",
            "tool_decision_format": "none",
            "should_include_tool_schema_in_prompt": False,
            "message_count": len(normalized_messages),
            "tool_count": 0,
        }

    def build_model_planning_request(
        self,
        *,
        provider_name: str,
        messages: List[Dict[str, Any]],
        prompt_envelope: Optional[Dict[str, Any]] = None,
        schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._normalize_provider_name(provider_name)
        normalized_messages = [dict(message) for message in (messages or [])]
        return {
            "provider": "router",
            "provider_family": "router",
            "messages": normalized_messages,
            "tools": [],
            "mode": "model_led_planning",
            "intent": "model_led_planning",
            "tool_choice_allowed": False,
            "native_tooling": False,
            "response_format": {"type": "json_object"},
            "temperature": 0.45,
            "schema": dict(schema or {}),
            "prompt_envelope": dict(prompt_envelope or {}),
            "prompt_mode": "model_led_planning",
            "structured_intent": "model_led_planning",
            "tool_prompting_strategy": "disabled",
            "tool_prompting_family": "router",
            "tool_decision_format": "none",
            "should_include_tool_schema_in_prompt": False,
            "message_count": len(normalized_messages),
            "tool_count": 0,
        }

    def build_reviewer_request(
        self,
        *,
        provider_name: str,
        prompt: str,
        schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._normalize_provider_name(provider_name)
        return {
            "provider": "router",
            "provider_family": "router",
            "prompt": str(prompt or ""),
            "mode": "schema_review",
            "intent": "soc_final_investigation_review",
            "native_tooling": False,
            "tool_prompting_strategy": "disabled",
            "tool_prompting_family": "router",
            "tool_decision_format": "none",
            "should_include_tool_schema_in_prompt": False,
            "response_format": {"type": "json_object"},
            "schema": dict(schema or {}),
        }

    def build_text_request(
        self,
        *,
        provider_name: str,
        prompt: str,
    ) -> Dict[str, Any]:
        self._normalize_provider_name(provider_name)
        return {
            "provider": "router",
            "provider_family": "router",
            "prompt": str(prompt or ""),
            "mode": "text_generation",
            "intent": "text_generation",
            "native_tooling": False,
            "tool_prompting_strategy": "disabled",
            "tool_prompting_family": "router",
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