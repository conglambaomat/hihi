import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.provider_chat_gateway import ProviderChatGateway


def test_build_chat_request_for_tool_decision_mode():
    gateway = ProviderChatGateway()

    request = gateway.build_chat_request(
        provider_name=" OpenRouter ",
        messages=[{"role": "user", "content": "Investigate 8.8.8.8"}],
        tools_json=[{"function": {"name": "investigate_ioc"}}],
        model_only_chat=False,
        prompt_envelope={
            "investigation_context": {"prompt_mode": "native_tooling"},
            "user_intent": {"mode": "native_tooling"},
        },
    )

    assert request["provider"] == "openrouter"
    assert request["provider_family"] == "openrouter"
    assert request["mode"] == "tool_decision"
    assert request["intent"] == "tool_decision"
    assert request["tool_choice_allowed"] is True
    assert request["native_tooling"] is True
    assert request["message_count"] == 1
    assert request["tool_count"] == 1
    assert request["prompt_mode"] == "native_tooling"
    assert request["structured_intent"] == "native_tooling"
    assert request["tool_prompting_strategy"] == "native_tools"
    assert request["tool_prompting_family"] == "openrouter"
    assert request["tool_decision_format"] == "native_tool_call"
    assert request["should_include_tool_schema_in_prompt"] is False
    assert request["prompt_envelope"]["user_intent"]["mode"] == "native_tooling"
    assert gateway.extract_chat_messages(request) == [{"role": "user", "content": "Investigate 8.8.8.8"}]
    assert gateway.extract_chat_tools(request) == [{"function": {"name": "investigate_ioc"}}]


def test_build_chat_request_for_direct_answer_mode_drops_tools():
    gateway = ProviderChatGateway()

    request = gateway.build_chat_request(
        provider_name="groq",
        messages=[{"role": "user", "content": "Summarize the current evidence"}],
        tools_json=[{"function": {"name": "investigate_ioc"}}],
        model_only_chat=True,
        prompt_envelope={
            "investigation_context": {"prompt_mode": "direct_answer"},
            "user_intent": {"mode": "direct_answer"},
        },
    )

    assert request["provider"] == "groq"
    assert request["provider_family"] == "groq"
    assert request["mode"] == "direct_answer"
    assert request["intent"] == "direct_answer"
    assert request["tool_choice_allowed"] is False
    assert request["native_tooling"] is False
    assert request["tool_count"] == 0
    assert request["prompt_mode"] == "direct_answer"
    assert request["structured_intent"] == "direct_answer"
    assert request["tool_prompting_strategy"] == "disabled"
    assert request["tool_decision_format"] == "none"
    assert request["should_include_tool_schema_in_prompt"] is False
    assert gateway.extract_chat_tools(request) == []


def test_build_chat_request_without_tools_uses_text_generation_mode():
    gateway = ProviderChatGateway()

    request = gateway.build_chat_request(
        provider_name="gemini",
        messages=[{"role": "user", "content": "Hello"}],
        tools_json=[],
        model_only_chat=False,
        prompt_envelope={
            "investigation_context": {"prompt_mode": "json_tool_decision"},
            "user_intent": {"mode": "json_tool_decision"},
        },
    )

    assert request["provider"] == "gemini"
    assert request["provider_family"] == "gemini"
    assert request["mode"] == "text_generation"
    assert request["intent"] == "text_generation"
    assert request["tool_choice_allowed"] is False
    assert request["native_tooling"] is False
    assert request["tool_count"] == 0
    assert request["prompt_mode"] == "json_tool_decision"
    assert request["structured_intent"] == "json_tool_decision"
    assert request["tool_prompting_strategy"] == "disabled"
    assert request["tool_decision_format"] == "none"
    assert request["should_include_tool_schema_in_prompt"] is False


def test_build_chat_request_aligns_non_openrouter_tool_prompting_to_json_contract():
    gateway = ProviderChatGateway()

    request = gateway.build_chat_request(
        provider_name="gemini",
        messages=[{"role": "user", "content": "Investigate suspicious IP"}],
        tools_json=[{"function": {"name": "investigate_ioc"}}],
        model_only_chat=False,
        prompt_envelope={
            "investigation_context": {"prompt_mode": "json_tool_decision"},
            "user_intent": {"mode": "json_tool_decision"},
        },
    )

    assert request["provider_family"] == "gemini"
    assert request["mode"] == "tool_decision"
    assert request["tool_choice_allowed"] is True
    assert request["tool_prompting_strategy"] == "aligned_tool_contract"
    assert request["tool_prompting_family"] == "gemini"
    assert request["tool_decision_format"] == "json_tool_decision"
    assert request["should_include_tool_schema_in_prompt"] is True


def test_build_text_request_normalizes_provider_and_prompt():
    gateway = ProviderChatGateway()

    request = gateway.build_text_request(
        provider_name=" NVIDIA ",
        prompt="Summarize findings",
    )

    assert request == {
        "provider": "nvidia",
        "provider_family": "nvidia",
        "prompt": "Summarize findings",
        "mode": "text_generation",
        "intent": "text_generation",
        "native_tooling": False,
        "tool_prompting_strategy": "disabled",
        "tool_prompting_family": "nvidia",
        "tool_decision_format": "none",
        "should_include_tool_schema_in_prompt": False,
    }
    assert gateway.extract_text_prompt(request) == "Summarize findings"