import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.provider_gateway import ProviderGateway


@pytest.mark.asyncio
async def test_chat_with_failover_uses_primary_provider_first():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    calls = []

    async def invoke(provider_name, messages, tools_payload):
        calls.append(provider_name)
        return {"provider": provider_name}

    result = await gateway.chat_with_failover(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
    )

    assert result == {"provider": "openrouter"}
    assert calls == ["openrouter"]
    logger.info.assert_not_called()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_with_failover_passes_request_metadata_to_extended_invoke_signature():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    calls = []

    async def invoke(provider_name, messages, tools_payload, request_metadata):
        calls.append(
            {
                "provider": provider_name,
                "messages": messages,
                "tools_payload": tools_payload,
                "request_metadata": request_metadata,
            }
        )
        return {"provider": provider_name, "mode": request_metadata.get("prompt_mode")}

    result = await gateway.chat_with_failover(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[{"function": {"name": "investigate_ioc"}}],
        request_metadata={"prompt_mode": "native_tooling", "structured_intent": "native_tooling"},
    )

    assert result == {"provider": "openrouter", "mode": "native_tooling"}
    assert calls == [
        {
            "provider": "openrouter",
            "messages": [{"role": "user", "content": "hello"}],
            "tools_payload": [{"function": {"name": "investigate_ioc"}}],
            "request_metadata": {"prompt_mode": "native_tooling", "structured_intent": "native_tooling"},
        }
    ]
    logger.info.assert_not_called()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_with_failover_keeps_backward_compatibility_for_legacy_invoke_signature_when_metadata_is_present():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    calls = []

    async def invoke(provider_name, messages, tools_payload):
        calls.append((provider_name, messages, tools_payload))
        return {"provider": provider_name, "message_count": len(messages)}

    result = await gateway.chat_with_failover(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
        request_metadata={"prompt_mode": "direct_answer"},
    )

    assert result == {"provider": "openrouter", "message_count": 1}
    assert calls == [("openrouter", [{"role": "user", "content": "hello"}], [])]
    logger.info.assert_not_called()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_with_failover_falls_back_and_logs_success():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    async def invoke(provider_name, messages, tools_payload):
        if provider_name == "openrouter":
            return None
        return {"provider": provider_name}

    result = await gateway.chat_with_failover(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
    )

    assert result == {"provider": "groq"}
    logger.info.assert_called_once()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_with_failover_logs_error_when_all_providers_fail():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    async def invoke(provider_name, messages, tools_payload):
        return None

    result = await gateway.chat_with_failover(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
    )

    assert result is None
    logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_chat_with_failover_continues_after_provider_exception():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    async def invoke(provider_name, messages, tools_payload):
        if provider_name == "openrouter":
            raise RuntimeError("provider offline")
        return {"provider": provider_name}

    result = await gateway.chat_with_failover(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
    )

    assert result == {"provider": "groq"}
    assert logger.info.call_count == 2
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_text_with_failover_returns_primary_text():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    async def invoke(provider_name, prompt):
        return f"{provider_name}:ok"

    result = await gateway.text_with_failover(
        invoke_provider_text=invoke,
        prompt="summarize",
    )

    assert result == "openrouter:ok"
    logger.info.assert_not_called()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_text_with_failover_uses_secondary_provider():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    async def invoke(provider_name, prompt):
        if provider_name == "openrouter":
            return None
        return f"{provider_name}:ok"

    result = await gateway.text_with_failover(
        invoke_provider_text=invoke,
        prompt="summarize",
    )

    assert result == "groq:ok"
    logger.info.assert_called_once()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_text_with_failover_continues_after_provider_exception():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["openrouter", "groq"],
        primary_provider=lambda: "openrouter",
        logger=logger,
    )

    async def invoke(provider_name, prompt):
        if provider_name == "openrouter":
            raise RuntimeError("provider offline")
        return f"{provider_name}:ok"

    result = await gateway.text_with_failover(
        invoke_provider_text=invoke,
        prompt="summarize",
    )

    assert result == "groq:ok"
    assert logger.info.call_count == 2
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_chat_provider_routes_to_expected_provider_handler():
    logger = MagicMock()
    request = {
        "provider": "groq",
        "messages": [{"role": "user", "content": "hello"}],
        "tools": [{"function": {"name": "investigate_ioc"}}],
    }

    invoke_ollama = AsyncMock(return_value="ollama")
    invoke_anthropic = AsyncMock(return_value="anthropic")
    invoke_groq = AsyncMock(return_value={"provider": "groq"})
    invoke_gemini = AsyncMock(return_value="gemini")
    invoke_nvidia = AsyncMock(return_value="nvidia")
    invoke_openrouter = AsyncMock(return_value="openrouter")

    result = await ProviderGateway.dispatch_chat_provider(
        provider_name=" groq ",
        request=request,
        extract_chat_messages=lambda payload: payload["messages"],
        extract_chat_tools=lambda payload: payload["tools"],
        invoke_ollama=invoke_ollama,
        invoke_anthropic=invoke_anthropic,
        invoke_groq=invoke_groq,
        invoke_gemini=invoke_gemini,
        invoke_nvidia=invoke_nvidia,
        invoke_openrouter=invoke_openrouter,
        logger=logger,
    )

    assert result == {"provider": "groq"}
    invoke_groq.assert_awaited_once_with(
        [{"role": "user", "content": "hello"}],
        [{"function": {"name": "investigate_ioc"}}],
    )
    invoke_ollama.assert_not_called()
    invoke_anthropic.assert_not_called()
    invoke_gemini.assert_not_called()
    invoke_nvidia.assert_not_called()
    invoke_openrouter.assert_not_called()
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_text_provider_routes_to_expected_provider_handler():
    logger = MagicMock()
    request = {
        "provider": "openrouter",
        "prompt": "summarize findings",
    }

    invoke_ollama = AsyncMock(return_value="ollama")
    invoke_anthropic = AsyncMock(return_value="anthropic")
    invoke_groq = AsyncMock(return_value="groq")
    invoke_gemini = AsyncMock(return_value="gemini")
    invoke_nvidia = AsyncMock(return_value="nvidia")
    invoke_openrouter = AsyncMock(return_value="openrouter:text")

    result = await ProviderGateway.dispatch_text_provider(
        provider_name="openrouter",
        request=request,
        extract_text_prompt=lambda payload: payload["prompt"],
        invoke_ollama=invoke_ollama,
        invoke_anthropic=invoke_anthropic,
        invoke_groq=invoke_groq,
        invoke_gemini=invoke_gemini,
        invoke_nvidia=invoke_nvidia,
        invoke_openrouter=invoke_openrouter,
        logger=logger,
    )

    assert result == "openrouter:text"
    invoke_openrouter.assert_awaited_once_with("summarize findings")
    invoke_ollama.assert_not_called()
    invoke_anthropic.assert_not_called()
    invoke_groq.assert_not_called()
    invoke_gemini.assert_not_called()
    invoke_nvidia.assert_not_called()
    logger.error.assert_not_called()
