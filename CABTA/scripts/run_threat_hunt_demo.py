#!/usr/bin/env python3
"""Run the built-in Threat Hunt playbook against a seeded demo case."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.agent_loop import AgentLoop
from src.agent.agent_store import AgentStore
from src.agent.governance_store import GovernanceStore
from src.agent.mcp_client import MCPClientManager, MCPServerConfig
from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry
from src.tools.ioc_investigator import IOCInvestigator
from src.utils.config import load_config


def _expand_placeholders(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("${PROJECT_ROOT}", str(PROJECT_ROOT))
    if isinstance(value, dict):
        return {key: _expand_placeholders(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_expand_placeholders(item) for item in value]
    return value


def _load_scenario(name: str) -> Dict[str, Any]:
    scenario_path = PROJECT_ROOT / "data" / "demo" / "threat_hunts" / f"{name}.json"
    with open(scenario_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Scenario '{name}' must be a JSON object")
    return _expand_placeholders(payload)


def _parse_jsonish(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return value


def _find_step(steps: list[Dict[str, Any]], needle: str) -> Dict[str, Any]:
    for step in steps:
        tool_name = str(step.get("tool_name") or "")
        content = str(step.get("content") or "")
        if needle in tool_name or needle in content:
            return step
    return {}


async def _connect_demo_servers(
    config: Dict[str, Any],
    mcp_client: MCPClientManager,
    tool_registry: ToolRegistry,
) -> Dict[str, Dict[str, Any]]:
    statuses: Dict[str, Dict[str, Any]] = {}
    wanted = {
        "free-osint",
        "osint-tools",
        "threat-intel-free",
        "network-analysis",
        "forensics-tools",
        "malwoverview",
        "remnux",
        "flare",
    }
    for entry in list(config.get("mcp_servers", []) or []):
        name = str(entry.get("name") or "").strip()
        if name not in wanted:
            continue
        server_cfg = MCPServerConfig.from_dict(entry)
        connected = await mcp_client.connect(server_cfg)
        tools = await mcp_client.list_tools(name) if connected else []
        if connected and tools:
            tool_registry.register_mcp_tools(name, tools)
        statuses[name] = {
            "connected": connected,
            "tool_count": len(tools),
            "error": mcp_client.get_connection_status().get(name, {}).get("error"),
        }
    return statuses


async def _run_demo(scenario_name: str, config_path: str | None) -> Dict[str, Any]:
    scenario = _load_scenario(scenario_name)
    config = load_config(config_path)

    # Keep the playbook evidence-first and deterministic for demos.
    config.setdefault("analysis", {})
    config["analysis"]["enable_llm"] = False

    log_hunting_cfg = config.setdefault("log_hunting", {})
    demo_cfg = log_hunting_cfg.setdefault("demo_backend", {})
    demo_cfg["enabled"] = True
    demo_cfg["dataset"] = str(scenario.get("log_dataset") or "threat_hunt_account_securecheck")

    with tempfile.TemporaryDirectory(prefix="cabta-threat-hunt-demo-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        agent_store = AgentStore(db_path=str(tmp_path / "agent.db"))
        governance_store = GovernanceStore(db_path=str(tmp_path / "governance.db"))
        mcp_client = MCPClientManager(agent_store=agent_store)
        tool_registry = ToolRegistry()
        ioc_investigator = IOCInvestigator(config)
        tool_registry.register_default_tools(
            config,
            ioc_investigator=ioc_investigator,
            mcp_client=mcp_client,
            governance_store=governance_store,
        )

        mcp_status = await _connect_demo_servers(config, mcp_client, tool_registry)

        agent_loop = AgentLoop(
            config=config,
            tool_registry=tool_registry,
            agent_store=agent_store,
            mcp_client=mcp_client,
            governance_store=governance_store,
        )
        engine = PlaybookEngine(
            agent_loop=agent_loop,
            agent_store=agent_store,
            governance_store=governance_store,
        )
        agent_loop._playbook_engine = engine

        session_id = await engine.execute(
            str(scenario.get("playbook_id") or "threat_hunt"),
            dict(scenario.get("default_inputs") or {}),
            wait_for_completion=True,
        )

        session = agent_store.get_session(session_id) or {}
        steps = agent_store.get_steps(session_id)
        decisions = governance_store.list_ai_decisions(session_id=session_id)

        execute_hunt_step = _find_step(steps, "search_logs")
        network_step = _find_step(steps, "analyze_network_iocs")
        whois_step = _find_step(steps, "whois_lookup")
        ssl_step = _find_step(steps, "ssl_certificate_info")
        zeek_step = _find_step(steps, "analyze_zeek_logs")
        suricata_step = _find_step(steps, "analyze_suricata_alerts")
        file_step = _find_step(steps, "file_metadata")
        yara_step = _find_step(steps, "yara_scan")
        final_step = steps[-1] if steps else {}

        called_tools = [step.get("tool_name") for step in steps if step.get("tool_name")]

        result = {
            "scenario": scenario_name,
            "playbook_id": scenario.get("playbook_id"),
            "session_id": session_id,
            "session_status": session.get("status"),
            "mcp_connections": mcp_status,
            "inputs": scenario.get("default_inputs"),
            "expected": scenario.get("expected"),
            "called_tools": called_tools,
            "log_hunt": _parse_jsonish(execute_hunt_step.get("tool_result")),
            "network_ioc_analysis": _parse_jsonish(network_step.get("tool_result")),
            "whois_lookup": _parse_jsonish(whois_step.get("tool_result")),
            "ssl_certificate_info": _parse_jsonish(ssl_step.get("tool_result")),
            "zeek_log_analysis": _parse_jsonish(zeek_step.get("tool_result")),
            "suricata_alert_analysis": _parse_jsonish(suricata_step.get("tool_result")),
            "file_metadata": _parse_jsonish(file_step.get("tool_result")),
            "yara_scan": _parse_jsonish(yara_step.get("tool_result")),
            "ai_decisions": decisions,
            "final_step": {
                "step_type": final_step.get("step_type"),
                "content": final_step.get("content"),
            },
            "steps": [
                {
                    "step_number": step.get("step_number"),
                    "step_type": step.get("step_type"),
                    "tool_name": step.get("tool_name"),
                    "content": step.get("content"),
                }
                for step in steps
            ],
        }

        await mcp_client.disconnect_all()
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        default="account_securecheck_case",
        help="Scenario name under data/demo/threat_hunts/",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Optional path to CABTA config.yaml",
    )
    args = parser.parse_args()

    result = asyncio.run(_run_demo(args.scenario, args.config))
    print(json.dumps(result, indent=2))

    if result.get("session_status") != "completed":
        return 1
    expected_count = int(result.get("expected", {}).get("results_count", 0) or 0)
    actual_count = int(result.get("log_hunt", {}).get("results_count", 0) or 0)
    return 0 if actual_count >= expected_count else 2


if __name__ == "__main__":
    raise SystemExit(main())
