import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.provider_gateway import ProviderGateway, ProviderGatewayError


@pytest.fixture
def gateway_and_logger():
    logger = MagicMock()
    gateway = ProviderGateway(
        candidate_providers=lambda: ["router"],
        primary_provider=lambda: "router",
        logger=logger,
    )
    return gateway, logger


@pytest.mark.asyncio
async def test_chat_uses_router_provider(gateway_and_logger):
    gateway, logger = gateway_and_logger
    calls = []

    async def invoke(provider_name, messages, tools_payload):
        calls.append((provider_name, messages, tools_payload))
        return {"provider": provider_name, "message_count": len(messages)}

    result = await gateway.chat(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
    )

    assert result == {"provider": "router", "message_count": 1}
    assert calls == [
        (
            "router",
            [{"role": "user", "content": "hello"}],
            [],
        )
    ]
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_passes_request_metadata_to_extended_invoke_signature(gateway_and_logger):
    gateway, logger = gateway_and_logger
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

    result = await gateway.chat(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[{"function": {"name": "investigate_ioc"}}],
        request_metadata={"prompt_mode": "native_tooling", "structured_intent": "native_tooling"},
    )

    assert result == {"provider": "router", "mode": "native_tooling"}
    assert calls == [
        {
            "provider": "router",
            "messages": [{"role": "user", "content": "hello"}],
            "tools_payload": [{"function": {"name": "investigate_ioc"}}],
            "request_metadata": {"prompt_mode": "native_tooling", "structured_intent": "native_tooling"},
        }
    ]
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_keeps_backward_compatibility_for_legacy_invoke_signature_when_metadata_is_present(gateway_and_logger):
    gateway, logger = gateway_and_logger
    calls = []

    async def invoke(provider_name, messages, tools_payload):
        calls.append((provider_name, messages, tools_payload))
        return {"provider": provider_name, "message_count": len(messages)}

    result = await gateway.chat(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
        request_metadata={"prompt_mode": "direct_answer"},
    )

    assert result == {"provider": "router", "message_count": 1}
    assert calls == [("router", [{"role": "user", "content": "hello"}], [])]
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_returns_none_when_router_returns_none(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, messages, tools_payload):
        return None

    result = await gateway.chat(
        invoke_provider_chat=invoke,
        messages=[{"role": "user", "content": "hello"}],
        tools_payload=[],
    )

    assert result is None
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_chat_logs_error_when_invoke_raises(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, messages, tools_payload):
        raise RuntimeError("router offline")

    with pytest.raises(ProviderGatewayError, match="router offline"):
        await gateway.chat(
            invoke_provider_chat=invoke,
            messages=[{"role": "user", "content": "hello"}],
            tools_payload=[],
        )

    logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_chat_logs_timeout_error_type_when_exception_has_empty_message(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, messages, tools_payload):
        raise TimeoutError()

    with pytest.raises(ProviderGatewayError, match="TimeoutError"):
        await gateway.chat(
            invoke_provider_chat=invoke,
            messages=[{"role": "user", "content": "hello"}],
            tools_payload=[],
        )

    logger.error.assert_called_once()
    assert "TimeoutError" in logger.error.call_args.args[1]


@pytest.mark.asyncio
async def test_text_uses_router_provider(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, prompt):
        return f"{provider_name}:{prompt}"

    result = await gateway.text(
        invoke_provider_text=invoke,
        prompt="summarize",
    )

    assert result == "router:summarize"
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_text_returns_none_when_router_returns_none(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, prompt):
        return None

    result = await gateway.text(
        invoke_provider_text=invoke,
        prompt="summarize",
    )

    assert result is None
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_text_logs_timeout_error_type_when_exception_has_empty_message(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, prompt):
        raise TimeoutError()

    with pytest.raises(ProviderGatewayError, match="TimeoutError"):
        await gateway.text(
            invoke_provider_text=invoke,
            prompt="summarize",
        )

    logger.error.assert_called_once()
    assert "TimeoutError" in logger.error.call_args.args[1]


@pytest.mark.asyncio
async def test_text_logs_error_when_invoke_raises(gateway_and_logger):
    gateway, logger = gateway_and_logger

    async def invoke(provider_name, prompt):
        raise RuntimeError("router offline")

    with pytest.raises(ProviderGatewayError, match="router offline"):
        await gateway.text(
            invoke_provider_text=invoke,
            prompt="summarize",
        )

    logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_dispatch_chat_provider_routes_to_router_handler():
    logger = MagicMock()
    request = {
        "provider": "router",
        "messages": [{"role": "user", "content": "hello"}],
        "tools": [{"function": {"name": "investigate_ioc"}}],
    }

    invoke_router = AsyncMock(return_value={"provider": "router"})

    result = await ProviderGateway.dispatch_chat_provider(
        provider_name=" router ",
        request=request,
        extract_chat_messages=lambda payload: payload["messages"],
        extract_chat_tools=lambda payload: payload["tools"],
        invoke_router=invoke_router,
        logger=logger,
    )

    assert result == {"provider": "router"}
    invoke_router.assert_awaited_once_with(
        [{"role": "user", "content": "hello"}],
        [{"function": {"name": "investigate_ioc"}}],
    )
    logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_text_provider_routes_to_router_handler():
    logger = MagicMock()
    request = {
        "provider": "router",
        "prompt": "summarize findings",
    }

    invoke_router = AsyncMock(return_value="router:text")

    result = await ProviderGateway.dispatch_text_provider(
        provider_name="router",
        request=request,
        extract_text_prompt=lambda payload: payload["prompt"],
        invoke_router=invoke_router,
        logger=logger,
    )

    assert result == "router:text"
    invoke_router.assert_awaited_once_with("summarize findings")
    logger.error.assert_not_called()
