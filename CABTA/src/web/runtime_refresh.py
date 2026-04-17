"""
Runtime refresh helpers for AISA web settings and MCP-aware tooling.
"""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Dict

logger = logging.getLogger(__name__)


def apply_runtime_config_bridges(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a config copy with runtime-only bridges applied.

    This keeps user-facing configuration simple while ensuring built-in MCP
    servers receive the credentials they need from the main API key store.
    """
    bridged = deepcopy(config or {})
    api_keys = bridged.setdefault("api_keys", {})
    mcp_servers = bridged.get("mcp_servers", [])

    abusech_key = (
        api_keys.get("abusech")
        or api_keys.get("threatfox")
        or ""
    )

    for server in mcp_servers:
        if not isinstance(server, dict):
            continue
        env = dict(server.get("env") or {})
        name = str(server.get("name", "")).strip()

        if name in {"threat-intel-free", "malwoverview"} and abusech_key:
            if not env.get("ABUSECH_AUTH_KEY"):
                env["ABUSECH_AUTH_KEY"] = abusech_key
            if not env.get("THREATFOX_AUTH_KEY"):
                env["THREATFOX_AUTH_KEY"] = abusech_key
            if not env.get("URLHAUS_AUTH_KEY"):
                env["URLHAUS_AUTH_KEY"] = abusech_key
            if not env.get("MALWAREBAZAAR_AUTH_KEY"):
                env["MALWAREBAZAAR_AUTH_KEY"] = abusech_key

        if env:
            server["env"] = env

    return bridged


async def reconnect_startup_mcp_servers(app) -> None:
    """Reconnect auto-connect MCP servers using the latest runtime config."""
    mcp_client = getattr(app.state, "mcp_client", None)
    if not mcp_client:
        return

    from src.agent.mcp_client import MCPServerConfig
    from src.web.routes.mcp_management import get_startup_mcp_server_configs

    configs = get_startup_mcp_server_configs(app)
    for cfg in configs:
        try:
            await mcp_client.connect(MCPServerConfig.from_dict(cfg))
        except Exception as exc:
            logger.warning("[CONFIG] Failed to reconnect MCP server %s: %s", cfg.get("name", "?"), exc)


async def refresh_runtime_components(app, config: Dict[str, Any]) -> None:
    """Rebuild long-lived runtime objects so web changes apply immediately."""
    from src.agent.agent_loop import AgentLoop
    from src.agent.playbook_engine import PlaybookEngine
    from src.agent.sandbox_orchestrator import SandboxOrchestrator
    from src.agent.tool_registry import ToolRegistry
    from src.daemon.service import HeadlessSOCDaemon
    from src.tools.email_analyzer import EmailAnalyzer
    from src.tools.ioc_investigator import IOCInvestigator
    from src.tools.malware_analyzer import MalwareAnalyzer
    from src.workflows.service import WorkflowService

    ioc_inv = None
    mal_ana = None
    email_ana = None

    try:
        ioc_inv = IOCInvestigator(config)
    except Exception as exc:
        logger.warning("[CONFIG] IOCInvestigator refresh failed: %s", exc)

    try:
        mal_ana = MalwareAnalyzer(config)
    except Exception as exc:
        logger.warning("[CONFIG] MalwareAnalyzer refresh failed: %s", exc)

    try:
        email_ana = EmailAnalyzer(config)
    except Exception as exc:
        logger.warning("[CONFIG] EmailAnalyzer refresh failed: %s", exc)

    if email_ana and ioc_inv:
        email_ana.ioc_investigator = ioc_inv
    if email_ana and mal_ana:
        email_ana.file_analyzer = mal_ana
    if mal_ana and ioc_inv:
        mal_ana.ioc_investigator = ioc_inv

    sandbox_orchestrator = None
    try:
        sandbox_orchestrator = SandboxOrchestrator(config, mcp_client=getattr(app.state, "mcp_client", None))
    except Exception as exc:
        logger.warning("[CONFIG] SandboxOrchestrator refresh failed: %s", exc)

    tool_registry = ToolRegistry()
    try:
        tool_registry.register_default_tools(
            config,
            ioc_investigator=ioc_inv,
            malware_analyzer=mal_ana,
            email_analyzer=email_ana,
            sandbox_orchestrator=sandbox_orchestrator,
            mcp_client=getattr(app.state, "mcp_client", None),
            governance_store=getattr(app.state, "governance_store", None),
            case_store=getattr(app.state, "case_store", None),
        )
    except Exception as exc:
        logger.warning("[CONFIG] Default tool registration refresh partial: %s", exc)

    mcp_client = getattr(app.state, "mcp_client", None)
    if mcp_client is not None:
        try:
            all_tools = await mcp_client.list_all_tools()
            for server_name, tools in all_tools.items():
                if tools:
                    tool_registry.register_mcp_tools(server_name, tools)
        except Exception as exc:
            logger.warning("[CONFIG] MCP tool refresh failed: %s", exc)

    agent_loop = None
    try:
        agent_loop = AgentLoop(
            config=config,
            tool_registry=tool_registry,
            agent_store=getattr(app.state, "agent_store", None),
            mcp_client=mcp_client,
            agent_profiles=getattr(app.state, "agent_profiles", None),
            workflow_registry=getattr(app.state, "workflow_registry", None),
            governance_store=getattr(app.state, "governance_store", None),
            case_store=getattr(app.state, "case_store", None),
        )
    except Exception as exc:
        logger.warning("[CONFIG] AgentLoop refresh failed: %s", exc)

    playbook_engine = None
    try:
        playbook_engine = PlaybookEngine(
            agent_loop=agent_loop,
            agent_store=getattr(app.state, "agent_store", None),
        )
        if agent_loop is not None:
            agent_loop._playbook_engine = playbook_engine
    except Exception as exc:
        logger.warning("[CONFIG] PlaybookEngine refresh failed: %s", exc)

    app.state.ioc_investigator = ioc_inv
    app.state.malware_analyzer = mal_ana
    app.state.email_analyzer = email_ana
    app.state.sandbox_orchestrator = sandbox_orchestrator
    app.state.tool_registry = tool_registry
    app.state.agent_loop = agent_loop
    app.state.playbook_engine = playbook_engine
    try:
        app.state.workflow_service = WorkflowService(
            workflow_registry=getattr(app.state, "workflow_registry", None),
            agent_store=getattr(app.state, "agent_store", None),
            case_store=getattr(app.state, "case_store", None),
        )
    except Exception as exc:
        logger.warning("[CONFIG] WorkflowService refresh failed: %s", exc)
    try:
        app.state.headless_soc_daemon = HeadlessSOCDaemon(
            config=config,
            workflow_registry=getattr(app.state, "workflow_registry", None),
            workflow_service=getattr(app.state, "workflow_service", None),
        )
    except Exception as exc:
        logger.warning("[CONFIG] HeadlessSOCDaemon refresh failed: %s", exc)

    if getattr(app.state, "web_provider", None) is not None:
        app.state.web_provider.config = config
