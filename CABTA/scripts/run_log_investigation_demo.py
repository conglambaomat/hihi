#!/usr/bin/env python3
"""Run the seeded log investigation playbook end-to-end and print the trace."""

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

from src.agent.agent_store import AgentStore
from src.agent.demo_log_backend import load_demo_log_dataset
from src.agent.governance_store import GovernanceStore
from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry
from src.utils.config import load_config


class LocalToolPlaybookLoop:
    """Small dispatcher that lets PlaybookEngine call local tools directly."""

    def __init__(self, tool_registry: ToolRegistry):
        self.tool_registry = tool_registry
        self.tool_calls = []

    async def run_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        execution_context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        execution_context = dict(execution_context or {})
        self.tool_calls.append(
            {
                "tool_name": tool_name,
                "params": params,
                "execution_context": execution_context,
            }
        )
        return await self.tool_registry.execute_local_tool(
            tool_name,
            _execution_context=execution_context,
            **params,
        )


def _parse_tool_result(step: Dict[str, Any]) -> Dict[str, Any]:
    raw = step.get("tool_result")
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


async def _run_demo(dataset: str, config_path: str | None) -> Dict[str, Any]:
    fixture = load_demo_log_dataset(dataset)
    playbook_id = str(fixture.get("playbook_id") or "log_investigation_demo")
    input_data = dict(fixture.get("default_inputs") or {})
    expected = dict(fixture.get("expected") or {})

    config = load_config(config_path)
    log_hunting_cfg = config.setdefault("log_hunting", {})
    demo_cfg = log_hunting_cfg.setdefault("demo_backend", {})
    demo_cfg["enabled"] = True
    demo_cfg["dataset"] = dataset

    with tempfile.TemporaryDirectory(prefix="cabta-playbook-demo-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        agent_store = AgentStore(db_path=str(tmp_path / "agent.db"))
        governance_store = GovernanceStore(db_path=str(tmp_path / "governance.db"))
        tool_registry = ToolRegistry()
        tool_registry.register_default_tools(
            config,
            governance_store=governance_store,
        )

        loop = LocalToolPlaybookLoop(tool_registry)
        engine = PlaybookEngine(
            agent_loop=loop,
            agent_store=agent_store,
            governance_store=governance_store,
        )

        session_id = await engine.execute(
            playbook_id,
            input_data,
            wait_for_completion=True,
        )

        session = agent_store.get_session(session_id) or {}
        steps = agent_store.get_steps(session_id)
        search_step = next(
            (step for step in steps if step.get("tool_name") == "search_logs"),
            {},
        )
        final_step = steps[-1] if steps else {}
        search_result = _parse_tool_result(search_step)

        return {
            "dataset": dataset,
            "playbook_id": playbook_id,
            "session_id": session_id,
            "status": session.get("status"),
            "expected": expected,
            "input_data": input_data,
            "tool_calls": loop.tool_calls,
            "search_logs_result": search_result,
            "final_answer": final_step.get("content", ""),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default="playbook_log_hunt",
        help="Seeded log-hunt dataset name under data/demo/log_hunts/",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Optional path to CABTA config.yaml",
    )
    args = parser.parse_args()

    result = asyncio.run(_run_demo(args.dataset, args.config))
    print(json.dumps(result, indent=2))

    if result.get("status") != "completed":
        return 1
    expected_results = int(result.get("expected", {}).get("results_count", 0) or 0)
    actual_results = int(result.get("search_logs_result", {}).get("results_count", 0) or 0)
    return 0 if actual_results >= expected_results else 2


if __name__ == "__main__":
    raise SystemExit(main())
