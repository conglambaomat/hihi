"""
Blue Team Agent - Comprehensive test suite for agent modules.

Tests cover:
  1. AgentState transitions (valid and invalid)
  2. AgentStore CRUD (sessions, steps, MCP connections, playbooks)
  3. ToolRegistry registration, lookup, get_tools_for_llm
  4. CorrelationEngine.correlate() with realistic findings
  5. InvestigationMemory remember/recall/TTL expiry
  6. PlaybookEngine condition evaluation (safe_evaluate_condition)
  7. SandboxOrchestrator.select_sandbox() file routing
  8. FastAPI endpoint tests

Author: Test Suite
"""

import asyncio
import json
import os
import sys
import time
from email.message import EmailMessage
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure project root is on sys.path for imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.agent_state import AgentPhase, AgentState
from src.agent.agent_store import AgentStore
from src.agent.tool_registry import ToolDefinition, ToolRegistry
from src.agent.correlation import CorrelationEngine
from src.agent.memory import InvestigationMemory
from src.agent.playbook_engine import PlaybookEngine, safe_evaluate_condition, PlaybookStep
from src.agent.sandbox_orchestrator import SandboxOrchestrator, SandboxType
from src.agent.mcp_client import MCPClientManager, MCPServerConfig, MCPConnection
from src.integrations.sandbox_integration import SandboxIntegration
from src.detection.llm_rule_generator import LLMRuleGenerator
from src.tools.email_analyzer import EmailAnalyzer


# ====================================================================== #
#  Fixtures
# ====================================================================== #

@pytest.fixture
def agent_state():
    """Fresh AgentState in IDLE phase."""
    return AgentState(goal="Investigate suspicious IP 10.0.0.1")


@pytest.fixture
def agent_store(tmp_path):
    """AgentStore backed by a temporary SQLite database."""
    db = tmp_path / "test_agent.db"
    return AgentStore(db_path=str(db))


@pytest.fixture
def tool_registry():
    """Empty ToolRegistry."""
    return ToolRegistry()


@pytest.fixture
def correlation_engine():
    """CorrelationEngine with default config."""
    return CorrelationEngine()


@pytest.fixture
def memory(tmp_path):
    """InvestigationMemory backed by a temporary database."""
    db = tmp_path / "test_memory.db"
    return InvestigationMemory(db_path=str(db))


@pytest.fixture
def playbook_engine(agent_store):
    """PlaybookEngine with a mocked agent_loop."""
    mock_loop = MagicMock()
    mock_loop.run_tool = AsyncMock(return_value={"result": "ok"})
    engine = PlaybookEngine(agent_loop=mock_loop, agent_store=agent_store)
    return engine


@pytest.fixture
def sandbox_orchestrator():
    """SandboxOrchestrator with no real Docker/subprocess."""
    return SandboxOrchestrator(config={})


@pytest.fixture
def mcp_manager():
    """MCPClientManager with no store."""
    return MCPClientManager(agent_store=None)


# ====================================================================== #
#  1. AgentState transitions
# ====================================================================== #

class TestAgentState:
    """Test AgentState phase transitions and helpers."""

    def test_initial_phase_is_idle(self, agent_state):
        assert agent_state.phase == AgentPhase.IDLE

    def test_valid_transition_idle_to_thinking(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        assert agent_state.phase == AgentPhase.THINKING

    def test_valid_transition_thinking_to_acting(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.ACTING)
        assert agent_state.phase == AgentPhase.ACTING

    def test_valid_transition_acting_to_observing(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.ACTING)
        agent_state.transition(AgentPhase.OBSERVING)
        assert agent_state.phase == AgentPhase.OBSERVING

    def test_valid_transition_observing_to_reflecting(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.ACTING)
        agent_state.transition(AgentPhase.OBSERVING)
        agent_state.transition(AgentPhase.REFLECTING)
        assert agent_state.phase == AgentPhase.REFLECTING

    def test_valid_transition_reflecting_to_completed(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.ACTING)
        agent_state.transition(AgentPhase.OBSERVING)
        agent_state.transition(AgentPhase.REFLECTING)
        agent_state.transition(AgentPhase.COMPLETED)
        assert agent_state.phase == AgentPhase.COMPLETED
        assert agent_state.is_terminal()

    def test_valid_transition_to_waiting_human(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.WAITING_HUMAN)
        assert agent_state.phase == AgentPhase.WAITING_HUMAN

    def test_valid_transition_waiting_human_to_thinking(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.WAITING_HUMAN)
        agent_state.transition(AgentPhase.THINKING)
        assert agent_state.phase == AgentPhase.THINKING

    def test_invalid_transition_idle_to_acting(self, agent_state):
        with pytest.raises(ValueError, match="Invalid transition"):
            agent_state.transition(AgentPhase.ACTING)

    def test_invalid_transition_idle_to_completed(self, agent_state):
        with pytest.raises(ValueError, match="Invalid transition"):
            agent_state.transition(AgentPhase.COMPLETED)

    def test_invalid_transition_completed_to_thinking(self, agent_state):
        agent_state.transition(AgentPhase.THINKING)
        agent_state.transition(AgentPhase.COMPLETED)
        with pytest.raises(ValueError, match="Invalid transition"):
            agent_state.transition(AgentPhase.THINKING)

    def test_invalid_transition_failed_is_terminal(self, agent_state):
        agent_state.transition(AgentPhase.FAILED)
        assert agent_state.is_terminal()
        with pytest.raises(ValueError):
            agent_state.transition(AgentPhase.THINKING)

    def test_add_finding(self, agent_state):
        agent_state.step_count = 3
        agent_state.add_finding({"tool": "yara", "matches": 2})
        assert len(agent_state.findings) == 1
        assert agent_state.findings[0]["step"] == 3
        assert agent_state.findings[0]["tool"] == "yara"
        assert "timestamp" in agent_state.findings[0]

    def test_request_and_clear_approval(self, agent_state):
        agent_state.request_approval(
            action={"tool": "block_ip", "ip": "1.2.3.4"},
            reason="Blocking a public IP requires analyst approval",
        )
        assert agent_state.pending_approval is not None
        assert agent_state.pending_approval["reason"].startswith("Blocking")

        approval = agent_state.clear_approval()
        assert approval is not None
        assert agent_state.pending_approval is None

    def test_to_dict(self, agent_state):
        d = agent_state.to_dict()
        assert d["phase"] == "idle"
        assert d["goal"] == "Investigate suspicious IP 10.0.0.1"
        assert d["is_terminal"] is False
        assert isinstance(d["session_id"], str)

    def test_is_terminal_false_for_non_terminal(self, agent_state):
        assert not agent_state.is_terminal()
        agent_state.transition(AgentPhase.THINKING)
        assert not agent_state.is_terminal()


# ====================================================================== #
#  2. AgentStore CRUD
# ====================================================================== #

class TestAgentStore:
    """Test AgentStore session, step, MCP, and playbook CRUD."""

    def test_create_and_get_session(self, agent_store):
        sid = agent_store.create_session(goal="Test investigation")
        assert isinstance(sid, str) and len(sid) == 12

        session = agent_store.get_session(sid)
        assert session is not None
        assert session["goal"] == "Test investigation"
        assert session["status"] == "active"

    def test_list_sessions(self, agent_store):
        agent_store.create_session(goal="Session A")
        agent_store.create_session(goal="Session B")
        sessions = agent_store.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_with_status_filter(self, agent_store):
        sid1 = agent_store.create_session(goal="Active one")
        sid2 = agent_store.create_session(goal="Completed one")
        agent_store.update_session_status(sid2, "completed", summary="Done")

        active = agent_store.list_sessions(status="active")
        assert len(active) == 1
        assert active[0]["goal"] == "Active one"

        completed = agent_store.list_sessions(status="completed")
        assert len(completed) == 1
        assert completed[0]["goal"] == "Completed one"

    def test_update_session_status(self, agent_store):
        sid = agent_store.create_session(goal="Will complete")
        agent_store.update_session_status(sid, "completed", summary="All done")
        session = agent_store.get_session(sid)
        assert session["status"] == "completed"
        assert session["summary"] == "All done"

    def test_update_session_findings(self, agent_store):
        sid = agent_store.create_session(goal="Findings test")
        findings = [{"tool": "yara", "matches": 3}]
        agent_store.update_session_findings(sid, findings)
        session = agent_store.get_session(sid)
        assert isinstance(session["findings"], list)
        assert session["findings"][0]["tool"] == "yara"

    def test_add_and_get_steps(self, agent_store):
        sid = agent_store.create_session(goal="Step test")
        step_id = agent_store.add_step(
            session_id=sid,
            step_number=1,
            step_type="tool_call",
            content="Investigating IOC",
            tool_name="investigate_ioc",
            tool_params='{"ioc": "1.2.3.4"}',
            tool_result='{"score": 80}',
            duration_ms=150,
        )
        assert isinstance(step_id, str) and len(step_id) == 12

        steps = agent_store.get_steps(sid)
        assert len(steps) == 1
        assert steps[0]["tool_name"] == "investigate_ioc"
        assert steps[0]["step_number"] == 1

    def test_get_steps_ordered(self, agent_store):
        sid = agent_store.create_session(goal="Order test")
        agent_store.add_step(sid, 2, "observe", "Step 2")
        agent_store.add_step(sid, 1, "think", "Step 1")
        agent_store.add_step(sid, 3, "reflect", "Step 3")
        steps = agent_store.get_steps(sid)
        assert [s["step_number"] for s in steps] == [1, 2, 3]

    def test_get_nonexistent_session(self, agent_store):
        assert agent_store.get_session("nonexistent") is None

    # ---- MCP Connections ---- #

    def test_save_and_list_mcp_connections(self, agent_store):
        agent_store.save_mcp_connection(
            name="remnux", transport="stdio",
            config={"command": "remnux-server", "args": []},
        )
        connections = agent_store.list_mcp_connections()
        assert len(connections) == 1
        assert connections[0]["name"] == "remnux"
        assert connections[0]["transport"] == "stdio"

    def test_update_mcp_status(self, agent_store):
        agent_store.save_mcp_connection(
            name="flare", transport="sse",
            config={"url": "http://localhost:8080"},
        )
        agent_store.update_mcp_status(
            name="flare", status="connected",
            tools=[{"name": "analyze", "description": "Analyze PE"}],
        )
        connections = agent_store.list_mcp_connections()
        flare = [c for c in connections if c["name"] == "flare"][0]
        assert flare["status"] == "connected"
        assert isinstance(flare["tools_json"], list)
        assert len(flare["tools_json"]) == 1

    def test_delete_mcp_connection(self, agent_store):
        agent_store.save_mcp_connection("to_delete", "stdio", {})
        agent_store.delete_mcp_connection("to_delete")
        assert len(agent_store.list_mcp_connections()) == 0

    def test_mcp_upsert(self, agent_store):
        agent_store.save_mcp_connection("srv", "stdio", {"v": 1})
        agent_store.save_mcp_connection("srv", "sse", {"v": 2})
        conns = agent_store.list_mcp_connections()
        assert len(conns) == 1
        assert conns[0]["transport"] == "sse"

    # ---- Playbooks ---- #

    def test_save_and_list_playbooks(self, agent_store):
        pid = agent_store.save_playbook(
            name="Phishing Investigation",
            description="Investigate a phishing email",
            steps=[{"name": "extract_iocs", "tool": "extract_iocs"}],
            trigger_type="manual",
        )
        assert isinstance(pid, str)

        playbooks = agent_store.list_playbooks()
        assert len(playbooks) == 1
        assert playbooks[0]["name"] == "Phishing Investigation"

    def test_get_playbook(self, agent_store):
        pid = agent_store.save_playbook(
            name="Malware Triage",
            description="Triage a malware sample",
            steps=[{"name": "scan", "tool": "yara_scan"}],
        )
        pb = agent_store.get_playbook(pid)
        assert pb is not None
        assert pb["name"] == "Malware Triage"
        assert isinstance(pb["steps_json"], list)

    def test_playbook_upsert(self, agent_store):
        agent_store.save_playbook("PB", "v1", [{"name": "s1", "tool": "t1"}])
        agent_store.save_playbook("PB", "v2", [{"name": "s2", "tool": "t2"}])
        pbs = agent_store.list_playbooks()
        assert len(pbs) == 1
        assert pbs[0]["description"] == "v2"

    # ---- Statistics ---- #

    def test_get_agent_stats(self, agent_store):
        sid1 = agent_store.create_session(goal="Stats A")
        sid2 = agent_store.create_session(goal="Stats B")
        agent_store.update_session_status(sid2, "completed")
        agent_store.add_step(sid1, 1, "think", "thinking")
        agent_store.add_step(sid1, 2, "act", "acting")

        stats = agent_store.get_agent_stats()
        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 1
        assert stats["completed_sessions"] == 1
        assert stats["total_steps"] == 2


# ====================================================================== #
#  3. ToolRegistry
# ====================================================================== #

class TestToolRegistry:
    """Test ToolRegistry registration, lookup, and LLM formatting."""

    def test_register_local_tool(self, tool_registry):
        async def dummy_exec(**kwargs):
            return {"result": "ok"}

        tool_registry.register_local_tool(
            name="scan_file",
            description="Scan a file with YARA",
            parameters={"type": "object", "properties": {"path": {"type": "string"}}},
            category="analysis",
            executor=dummy_exec,
        )
        tool = tool_registry.get_tool("scan_file")
        assert tool is not None
        assert tool.name == "scan_file"
        assert tool.source == "local"
        assert tool.category == "analysis"

    def test_register_mcp_tools(self, tool_registry):
        tool_registry.register_mcp_tools("remnux", [
            {"name": "strings", "description": "Extract strings", "inputSchema": {}},
            {"name": "file_info", "description": "File info", "inputSchema": {}},
        ])
        assert tool_registry.get_tool("remnux.strings") is not None
        assert tool_registry.get_tool("remnux.file_info") is not None
        assert tool_registry.get_tool("remnux.nonexistent") is None

    def test_list_tools_all(self, tool_registry):
        async def noop(**kw):
            return {}
        tool_registry.register_local_tool("t1", "d1", {}, "analysis", noop)
        tool_registry.register_local_tool("t2", "d2", {}, "threat_intel", noop)
        assert len(tool_registry.list_tools()) == 2

    def test_list_tools_by_category(self, tool_registry):
        async def noop(**kw):
            return {}
        tool_registry.register_local_tool("t1", "d1", {}, "analysis", noop)
        tool_registry.register_local_tool("t2", "d2", {}, "threat_intel", noop)
        assert len(tool_registry.list_tools(category="analysis")) == 1
        assert len(tool_registry.list_tools(category="threat_intel")) == 1
        assert len(tool_registry.list_tools(category="forensics")) == 0

    def test_list_tools_by_source(self, tool_registry):
        async def noop(**kw):
            return {}
        tool_registry.register_local_tool("t1", "d1", {}, "analysis", noop)
        tool_registry.register_mcp_tools("srv", [{"name": "remote_t", "description": "Remote"}])
        assert len(tool_registry.list_tools(source="local")) == 1
        assert len(tool_registry.list_tools(source="srv")) == 1

    def test_unregister_server(self, tool_registry):
        tool_registry.register_mcp_tools("srv", [
            {"name": "a", "description": "A"},
            {"name": "b", "description": "B"},
        ])
        removed = tool_registry.unregister_server("srv")
        assert removed == 2
        assert tool_registry.get_tool("srv.a") is None

    def test_get_tools_for_llm(self, tool_registry):
        async def noop(**kw):
            return {}
        tool_registry.register_local_tool(
            "investigate_ioc", "Investigate an IOC", {"type": "object"}, "ti", noop,
            requires_approval=True,
        )
        llm_tools = tool_registry.get_tools_for_llm()
        assert len(llm_tools) == 1
        fn = llm_tools[0]
        assert fn["type"] == "function"
        assert fn["function"]["name"] == "investigate_ioc"
        assert "[REQUIRES APPROVAL]" in fn["function"]["description"]

    @pytest.mark.asyncio
    async def test_execute_local_tool(self, tool_registry):
        async def mock_exec(ioc="", **kw):
            return {"score": 75, "verdict": "suspicious"}
        tool_registry.register_local_tool("check", "Check IOC", {}, "ti", mock_exec)

        result = await tool_registry.execute_local_tool("check", ioc="1.2.3.4")
        assert result["score"] == 75

    @pytest.mark.asyncio
    async def test_execute_local_tool_missing(self, tool_registry):
        result = await tool_registry.execute_local_tool("nonexistent")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_local_tool_exception(self, tool_registry):
        async def failing(**kw):
            raise RuntimeError("boom")
        tool_registry.register_local_tool("fail", "Fail", {}, "x", failing)
        result = await tool_registry.execute_local_tool("fail")
        assert "error" in result
        assert "boom" in result["error"]

    @pytest.mark.asyncio
    async def test_register_default_tools_uses_injected_sandbox_orchestrator(self, tool_registry):
        mock_orch = MagicMock()
        mock_orch.select_sandbox.return_value = {"sandbox_type": "local_static"}
        mock_orch.submit_to_sandbox = AsyncMock(return_value={"status": "completed", "sandbox_type": "local_static"})

        tool_registry.register_default_tools({}, sandbox_orchestrator=mock_orch)

        result = await tool_registry.execute_local_tool("sandbox_submit", file_path="C:/samples/test.bin")

        mock_orch.select_sandbox.assert_called_once_with("C:/samples/test.bin")
        mock_orch.submit_to_sandbox.assert_awaited_once_with("C:/samples/test.bin", "local_static")
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_generate_rules_supports_hunt_context(self, tool_registry):
        tool_registry.register_default_tools({})

        result = await tool_registry.execute_local_tool(
            "generate_rules",
            analysis_result={
                "hypothesis": "Suspicious outbound C2 communications from finance workstation",
                "known_iocs": {
                    "ips": ["185.220.101.45"],
                    "domains": ["secure-payroll-check.com"],
                    "hashes": ["44d88612fea8a8f36de82e1278abb02f4fc66b0c5d7d5e8f4c4c286f4a9f0f12"],
                },
            },
            rule_types=["kql", "spl", "sigma", "snort"],
        )

        assert result["status"] == "generated"
        assert result["query_count"] >= 3
        assert "queries" in result
        assert "kql" in result["queries"]
        assert isinstance(result["queries"]["kql"], list)
        assert "snort" in result["queries"]

    @pytest.mark.asyncio
    async def test_search_logs_returns_honest_manual_status_without_backend(self, tool_registry):
        tool_registry.register_default_tools({})

        result = await tool_registry.execute_local_tool(
            "search_logs",
            query={"spl": ['index=* earliest=-24h | search dest_ip="185.220.101.45"']},
            timerange="24h",
        )

        assert result["status"] == "manual_lookup_required"
        assert result["results_count"] == 0
        assert result["query_count"] == 1
        assert result["queries"]["spl"]


# ====================================================================== #
#  4. CorrelationEngine
# ====================================================================== #

class TestCorrelationEngine:
    """Test CorrelationEngine.correlate() with realistic findings."""

    def test_correlate_empty_findings(self, correlation_engine):
        result = correlation_engine.correlate([])
        assert result["severity"] == "info"
        assert result["statistics"]["total_findings"] == 0

    def test_correlate_single_finding_no_overlaps(self, correlation_engine):
        findings = [{"type": "ioc_lookup", "ips": ["45.33.32.156"], "verdict": "clean"}]
        result = correlation_engine.correlate(findings)
        assert result["ioc_overlaps"] == []
        assert result["severity"] in ("info", "low")

    def test_correlate_overlapping_iocs(self, correlation_engine):
        """Two findings sharing the same IP should produce an overlap."""
        findings = [
            {
                "type": "email_analysis",
                "result": {"urls": ["http://evil.com/payload"], "ips": ["45.33.32.156"]},
            },
            {
                "type": "sandbox_result",
                "result": {"c2_servers": ["45.33.32.156"], "verdict": "malicious"},
            },
        ]
        result = correlation_engine.correlate(findings)
        overlapping_iocs = [o["ioc"] for o in result["ioc_overlaps"]]
        assert "45.33.32.156" in overlapping_iocs

    def test_correlate_detects_ttp_powershell(self, correlation_engine):
        findings = [
            {"type": "sandbox", "result": {"output": "powershell -enc base64string"}},
        ]
        result = correlation_engine.correlate(findings)
        technique_ids = [t["technique_id"] for t in result["ttp_matches"]]
        assert "T1059.001" in technique_ids  # PowerShell

    def test_correlate_detects_ttp_ransomware(self, correlation_engine):
        findings = [
            {"type": "analysis", "result": {"description": "ransomware encryption detected"}},
        ]
        result = correlation_engine.correlate(findings)
        technique_ids = [t["technique_id"] for t in result["ttp_matches"]]
        assert "T1486" in technique_ids  # Data Encrypted for Impact

    def test_correlate_c2_and_lateral_movement_high_severity(self, correlation_engine):
        findings = [
            {"type": "network", "result": {"description": "c2 beacon detected on tor network via smb"}},
            {"type": "edr", "result": {"description": "psexec lateral movement mimikatz credential dump"}},
            {"type": "sandbox", "verdict": "malicious"},
        ]
        result = correlation_engine.correlate(findings)
        assert result["severity"] in ("high", "critical")

    def test_correlate_builds_entity_graph(self, correlation_engine):
        findings = [
            {
                "type": "analysis",
                "ips": ["45.33.32.156"],
                "domains": ["evil.com"],
                "sha256": ["a" * 64],
            },
        ]
        result = correlation_engine.correlate(findings)
        assert isinstance(result["entity_graph"], dict)

    def test_correlate_statistics(self, correlation_engine):
        findings = [
            {"type": "ioc", "ips": ["45.33.32.156", "203.0.113.1"]},
            {"type": "ioc", "domains": ["malware.xyz"]},
        ]
        result = correlation_engine.correlate(findings)
        stats = result["statistics"]
        assert stats["total_findings"] == 2
        assert stats["unique_iocs"] >= 2

    def test_structured_mitre_references(self, correlation_engine):
        findings = [
            {
                "type": "analysis",
                "mitre_attck": "T1055",
                "technique_name": "Process Injection",
                "tactic": "defense-evasion",
            },
        ]
        result = correlation_engine.correlate(findings)
        technique_ids = [t["technique_id"] for t in result["ttp_matches"]]
        assert "T1055" in technique_ids

    # ---- Stateful correlation ---- #

    def test_add_findings_and_correlate_ioc(self, correlation_engine):
        findings = [{"tool": "vt", "ips": ["45.33.32.156"]}]
        new_count = correlation_engine.add_findings("sess1", findings)
        assert new_count >= 1

        info = correlation_engine.correlate_ioc("45.33.32.156")
        assert info["seen_count"] >= 1
        assert "sess1" in info["sessions"]

    def test_clear_session(self, correlation_engine):
        correlation_engine.add_findings("s1", [{"tool": "x", "ips": ["45.33.32.156"]}])
        correlation_engine.clear_session("s1")
        stats = correlation_engine.get_stats()
        assert stats["total_sessions_indexed"] == 0


# ====================================================================== #
#  5. InvestigationMemory
# ====================================================================== #

class TestInvestigationMemory:
    """Test InvestigationMemory remember/recall/TTL."""

    def test_remember_and_recall_ioc(self, memory):
        memory.remember_ioc("1.2.3.4", {"score": 80, "verdict": "malicious"})
        result = memory.recall_ioc("1.2.3.4")
        assert result is not None
        assert result["score"] == 80

    def test_recall_unknown_ioc_returns_none(self, memory):
        assert memory.recall_ioc("unknown.example.com") is None

    def test_ttl_expiry(self, memory):
        """IOC with TTL=0 should be considered expired immediately."""
        # Insert with ttl_hours=0 (already expired on next read)
        memory.remember_ioc("expired.com", {"score": 50}, ttl_hours=0)
        # The in-memory cache will have it, but _is_expired should catch it
        # We need to simulate passage of time. Patch _is_expired to return True
        # for this IOC, or use a very small TTL and manipulate the timestamp.
        # Easier: directly test the _is_expired method.
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        assert InvestigationMemory._is_expired(past, 1) is True

    def test_not_expired(self, memory):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        assert InvestigationMemory._is_expired(future, 24) is False

    def test_is_expired_empty_string(self, memory):
        assert InvestigationMemory._is_expired("", 24) is True

    def test_forget_ioc(self, memory):
        memory.remember_ioc("forget.me", {"x": 1})
        memory.forget_ioc("forget.me")
        assert memory.recall_ioc("forget.me") is None

    def test_list_cached_iocs(self, memory):
        memory.remember_ioc("a.com", {"s": 1})
        memory.remember_ioc("b.com", {"s": 2})
        cached = memory.list_cached_iocs()
        assert len(cached) == 2

    def test_record_pattern(self, memory):
        memory.record_pattern("c2_infra", "Cobalt Strike on port 443")
        memory.record_pattern("c2_infra", "Cobalt Strike on port 443")
        patterns = memory.get_frequent_patterns(min_frequency=2)
        assert len(patterns) == 1
        assert patterns[0]["frequency"] == 2

    def test_record_pattern_different_types(self, memory):
        memory.record_pattern("malware_family", "Emotet loader")
        memory.record_pattern("malware_family", "Emotet loader")
        memory.record_pattern("c2_infra", "Cobalt Strike beacon")
        summary = memory.get_pattern_summary()
        assert summary["cached_iocs"] == 0
        assert summary["total_patterns"] >= 2

    def test_get_frequent_patterns_with_type_filter(self, memory):
        memory.record_pattern("type_a", "pattern 1")
        memory.record_pattern("type_a", "pattern 1")
        memory.record_pattern("type_b", "pattern 2")
        memory.record_pattern("type_b", "pattern 2")
        patterns = memory.get_frequent_patterns(pattern_type="type_a", min_frequency=2)
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "type_a"

    def test_purge_expired(self, memory):
        # Store an IOC then manipulate its timestamp in the DB to make it expired
        memory.remember_ioc("old.com", {"x": 1}, ttl_hours=1)
        # Directly update the DB to set an old timestamp
        conn = memory._connect()
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn.execute("UPDATE ioc_cache SET queried_at = ? WHERE ioc = ?", (old_ts, "old.com"))
        conn.commit()
        conn.close()
        # Clear in-memory cache so purge checks DB
        memory._ioc_mem_cache.clear()

        removed = memory.purge_expired()
        assert removed == 1
        assert memory.recall_ioc("old.com") is None


# ====================================================================== #
#  6. PlaybookEngine condition evaluation
# ====================================================================== #

class TestPlaybookConditions:
    """Test safe_evaluate_condition with various condition patterns."""

    def test_empty_condition_returns_true(self):
        assert safe_evaluate_condition("", {}) is True
        assert safe_evaluate_condition("  ", {}) is True

    def test_simple_equality(self):
        assert safe_evaluate_condition("verdict == 'MALICIOUS'", {"verdict": "MALICIOUS"})

    def test_simple_inequality(self):
        assert safe_evaluate_condition("verdict != 'CLEAN'", {"verdict": "MALICIOUS"})

    def test_numeric_greater_than(self):
        assert safe_evaluate_condition("score > 70", {"score": 80})
        assert not safe_evaluate_condition("score > 70", {"score": 50})

    def test_numeric_greater_equal(self):
        assert safe_evaluate_condition("score >= 70", {"score": 70})

    def test_numeric_less_than(self):
        assert safe_evaluate_condition("score < 50", {"score": 30})
        assert not safe_evaluate_condition("score < 50", {"score": 80})

    def test_numeric_less_equal(self):
        assert safe_evaluate_condition("score <= 50", {"score": 50})

    def test_value_in_list(self):
        ctx = {"tags": ["ransomware", "trojan", "c2"]}
        assert safe_evaluate_condition("'ransomware' in tags", ctx)
        assert not safe_evaluate_condition("'worm' in tags", ctx)

    def test_value_in_string(self):
        ctx = {"description": "This is a ransomware attack"}
        assert safe_evaluate_condition("'ransomware' in description", ctx)

    def test_variable_in_tuple(self):
        ctx = {"file_type": "PE"}
        assert safe_evaluate_condition("file_type in ('PE', 'ELF')", ctx)
        assert not safe_evaluate_condition("file_type in ('APK', 'JAR')", ctx)

    def test_and_condition(self):
        ctx = {"score": 80, "verdict": "MALICIOUS"}
        assert safe_evaluate_condition("score > 70 and verdict == 'MALICIOUS'", ctx)
        assert not safe_evaluate_condition("score > 90 and verdict == 'MALICIOUS'", ctx)

    def test_or_condition(self):
        ctx = {"score": 40, "verdict": "MALICIOUS"}
        assert safe_evaluate_condition("score > 70 or verdict == 'MALICIOUS'", ctx)
        assert not safe_evaluate_condition("score > 70 or verdict == 'CLEAN'", ctx)

    def test_boolean_literal(self):
        assert safe_evaluate_condition("flag == true", {"flag": True})
        assert safe_evaluate_condition("flag == false", {"flag": False})

    def test_none_literal(self):
        assert safe_evaluate_condition("x == none", {"x": None})

    def test_dotted_variable_path(self):
        ctx = {"result": {"score": 85}}
        assert safe_evaluate_condition("result.score > 80", ctx)

    def test_last_result_flattening(self):
        ctx = {"last_result": {"verdict": "MALICIOUS"}}
        assert safe_evaluate_condition("verdict == 'MALICIOUS'", ctx)

    def test_ratio_like_scores_compare_numerically(self):
        ctx = {"sender_email_security": {"score": "1/3"}}
        assert safe_evaluate_condition("{{sender_email_security.score}} < '2/3'", ctx)

    def test_unrecognised_pattern_returns_false(self):
        assert safe_evaluate_condition("some weird stuff !@#", {}) is False

    def test_missing_variable_returns_false(self):
        assert safe_evaluate_condition("nonexistent > 10", {}) is False

    def test_template_wrapped_truthy_variable(self):
        ctx = {"extract_alert_iocs": {"sender_domains": ["evil.com"]}}
        assert safe_evaluate_condition("{{extract_alert_iocs.sender_domains}}", ctx)

    def test_template_wrapped_numeric_comparison(self):
        ctx = {"execute_hunt": {"results_count": 2}}
        assert safe_evaluate_condition("{{execute_hunt.results_count}} > 0", ctx)

    def test_bare_variable_truthiness(self):
        ctx = {"extract_file_iocs": {"urls": ["http://evil.test"]}}
        assert safe_evaluate_condition("extract_file_iocs.urls", ctx)


class TestPlaybookStep:
    """Test PlaybookStep serialisation."""

    def test_from_dict_and_to_dict(self):
        d = {
            "name": "step1",
            "tool": "investigate_ioc",
            "params": {"ioc": "1.2.3.4"},
            "condition": "score > 50",
            "on_success": "step2",
            "on_failure": "end",
            "requires_approval": True,
            "timeout": 60,
            "description": "Investigate the IOC",
        }
        step = PlaybookStep.from_dict(d)
        assert step.name == "step1"
        assert step.requires_approval is True

        out = step.to_dict()
        assert out["tool"] == "investigate_ioc"
        assert out["condition"] == "score > 50"

    def test_condition_dict_self_then_becomes_sequential(self):
        step = PlaybookStep.from_dict({
            "name": "urlhaus_check",
            "tool": "mcp:threat-intel-free/urlhaus_lookup",
            "condition": {"if": "extract_file_iocs.urls", "then": "urlhaus_check", "else": "feodo_check"},
        })
        assert step.on_success is None
        assert step.on_failure == "feodo_check"


class TestPlaybookEngine:
    """Test PlaybookEngine registration and listing."""

    def test_register_playbook(self, playbook_engine):
        pid = playbook_engine.register_playbook(
            name="Test Playbook",
            description="A test",
            steps=[{"name": "s1", "tool": "t1", "params": {}}],
        )
        assert isinstance(pid, str)
        pb = playbook_engine.get_playbook(pid)
        assert pb is not None
        assert pb["name"] == "Test Playbook"

    def test_list_playbooks(self, playbook_engine):
        playbook_engine.register_playbook("PB1", "D1", [{"name": "s", "tool": "t"}])
        playbook_engine.register_playbook("PB2", "D2", [{"name": "s", "tool": "t"}])
        pbs = playbook_engine.list_playbooks()
        names = [p["name"] for p in pbs]
        assert "PB1" in names
        assert "PB2" in names

    def test_get_nonexistent_playbook(self, playbook_engine):
        assert playbook_engine.get_playbook("nonexistent") is None

    def test_list_available_alias(self, playbook_engine):
        playbook_engine.register_playbook("PB", "D", [{"name": "s", "tool": "t"}])
        assert playbook_engine.list_available() == playbook_engine.list_playbooks()

    @pytest.mark.asyncio
    async def test_execute_playbook(self, playbook_engine, agent_store):
        pid = playbook_engine.register_playbook(
            name="Simple PB",
            description="One step",
            steps=[{"name": "step1", "tool": "investigate_ioc", "params": {"ioc": "1.2.3.4"}}],
        )
        session_id = await playbook_engine.execute(pid, {"ioc": "1.2.3.4"}, wait_for_completion=True)
        assert isinstance(session_id, str)

        # Verify the session was completed
        session = agent_store.get_session(session_id)
        assert session["status"] == "completed"
        assert session["metadata"]["execution_mode"] == "playbook"
        assert session["metadata"]["max_steps"] == 1

    @pytest.mark.asyncio
    async def test_execute_playbook_runs_in_background_by_default(self, playbook_engine, agent_store):
        pid = playbook_engine.register_playbook(
            name="Async PB",
            description="Background execution",
            steps=[{"name": "step1", "tool": "investigate_ioc", "params": {"ioc": "1.2.3.4"}}],
        )
        session_id = await playbook_engine.execute(pid, {"ioc": "1.2.3.4"})
        assert isinstance(session_id, str)

        session = agent_store.get_session(session_id)
        assert session["metadata"]["execution_mode"] == "playbook"
        assert session["metadata"]["max_steps"] == 1

        for _ in range(50):
            session = agent_store.get_session(session_id)
            if session["status"] == "completed":
                break
            await asyncio.sleep(0.02)

        assert session["status"] == "completed"

    @pytest.mark.asyncio
    async def test_execute_nonexistent_playbook_raises(self, playbook_engine):
        with pytest.raises(ValueError, match="not found"):
            await playbook_engine.execute("nonexistent", {})

    def test_interpolate_string(self, playbook_engine):
        result = PlaybookEngine._interpolate_string(
            "Analyzing {{file_path}} for IOC {{ioc}}",
            {"file_path": "/tmp/mal.exe", "ioc": "1.2.3.4"},
        )
        assert result == "Analyzing /tmp/mal.exe for IOC 1.2.3.4"

    def test_interpolate_string_unresolved(self, playbook_engine):
        result = PlaybookEngine._interpolate_string(
            "Value: {{missing}}",
            {},
        )
        assert result == "Value: {{missing}}"

    def test_interpolate_params_preserves_raw_objects(self, playbook_engine):
        context = {
            "known_indicators": {
                "ips": ["185.220.101.45"],
                "domains": ["secure-payroll-check.com"],
            },
            "build_hunt_queries": {
                "queries": {
                    "spl": ['index=* earliest=-24h | search dest_ip="185.220.101.45"'],
                }
            },
        }

        result = playbook_engine._interpolate_params(
            {
                "iocs": "{{known_indicators}}",
                "query": "{{build_hunt_queries.queries}}",
            },
            context,
        )

        assert isinstance(result["iocs"], dict)
        assert result["iocs"]["ips"] == ["185.220.101.45"]
        assert isinstance(result["query"], dict)
        assert "spl" in result["query"]

    @pytest.mark.asyncio
    async def test_for_each_results_are_aggregated_for_follow_on_conditions(self, playbook_engine, agent_store):
        playbook_engine.agent_loop.run_tool = AsyncMock(side_effect=[
            {"malicious": False, "ioc": "benign.example"},
            {"malicious": True, "ioc": "evil.example"},
        ])

        pid = playbook_engine.register_playbook(
            name="Iter Aggregate",
            description="Ensure for_each sets aggregate context",
            steps=[
                {
                    "name": "lookup",
                    "tool": "mcp:test/check",
                    "for_each": "items",
                    "params": {"indicator": "{{item}}"},
                },
                {
                    "name": "decision",
                    "condition": {"if": "{{lookup.malicious}}", "then": "flagged", "else": "clean"},
                },
                {"name": "flagged", "action": "final_answer", "description": "Threat confirmed"},
                {"name": "clean", "action": "final_answer", "description": "No threat found"},
            ],
        )

        session_id = await playbook_engine.execute(
            pid,
            {"items": ["benign.example", "evil.example"]},
            wait_for_completion=True,
        )

        steps = agent_store.get_steps(session_id)
        assert any(step["step_type"] == "for_each_iteration" for step in steps)
        assert any(step["step_type"] == "final_answer" and "Threat confirmed" in step["content"] for step in steps)

    def test_get_builtin_playbook_includes_input_params(self, playbook_engine):
        pb = playbook_engine.get_playbook("alert_triage")
        assert pb is not None
        assert isinstance(pb.get("input_params"), list)
        assert any(item.get("name") == "alert_text" for item in pb["input_params"] if isinstance(item, dict))
        assert "alert_text" in pb.get("parameters", {})

    @pytest.mark.asyncio
    async def test_execute_branch_only_condition_routes_else(self, playbook_engine, agent_store):
        pid = playbook_engine.register_playbook(
            name="Branch Only",
            description="Route to low branch",
            steps=[
                {
                    "name": "priority_gate",
                    "condition": {"if": "score > 50", "then": "high", "else": "low"},
                },
                {"name": "high", "action": "final_answer", "description": "High branch"},
                {"name": "low", "action": "final_answer", "description": "Low branch"},
            ],
        )
        session_id = await playbook_engine.execute(pid, {"score": 10}, wait_for_completion=True)
        steps = agent_store.get_steps(session_id)
        assert len(steps) == 1
        assert steps[0]["step_type"] == "final_answer"
        assert "Low branch" in steps[0]["content"]

    @pytest.mark.asyncio
    async def test_execute_condition_guard_true_with_self_then_falls_through(self, playbook_engine, agent_store):
        pid = playbook_engine.register_playbook(
            name="Guard Self",
            description="Execute guarded tool once",
            steps=[
                {
                    "name": "guarded_lookup",
                    "tool": "investigate_ioc",
                    "params": {"ioc": "{{ioc}}"},
                    "condition": {"if": "items", "then": "guarded_lookup", "else": "fallback"},
                },
                {"name": "after_guard", "action": "final_answer", "description": "Executed guarded step"},
                {"name": "fallback", "action": "final_answer", "description": "Skipped guarded step"},
            ],
        )
        session_id = await playbook_engine.execute(
            pid,
            {"ioc": "1.2.3.4", "items": ["1.2.3.4"]},
            wait_for_completion=True,
        )
        steps = agent_store.get_steps(session_id)
        assert any(step["step_type"] == "tool_call" and step["tool_name"] == "investigate_ioc" for step in steps)
        assert any("Executed guarded step" in step["content"] for step in steps)
        assert not any("Skipped guarded step" in step["content"] for step in steps)

    @pytest.mark.asyncio
    async def test_resume_playbook_approval(self, playbook_engine, agent_store):
        pid = playbook_engine.register_playbook(
            name="Approval PB",
            description="Pause then resume",
            steps=[
                {
                    "name": "sandbox_gate",
                    "tool": "sandbox_submit",
                    "params": {"file_path": "sample.exe"},
                    "requires_approval": True,
                },
                {"name": "wrap_up", "action": "final_answer", "description": "Done"},
            ],
        )

        session_id = await playbook_engine.execute(pid, {"file_path": "sample.exe"})
        for _ in range(50):
            session = agent_store.get_session(session_id)
            pending = (session.get("metadata") or {}).get("pending_approval")
            if session["status"] == "waiting_approval" and pending:
                break
            await asyncio.sleep(0.02)

        assert session["status"] == "waiting_approval"
        assert session["metadata"]["pending_approval"]["tool"] == "sandbox_submit"

        resumed = await playbook_engine.resume_approval(session_id, True)
        assert resumed is True

        for _ in range(50):
            session = agent_store.get_session(session_id)
            if session["status"] == "completed":
                break
            await asyncio.sleep(0.02)

        steps = agent_store.get_steps(session_id)
        assert session["status"] == "completed"
        assert any(step["step_type"] == "approval_granted" for step in steps)
        assert any(step["step_type"] == "tool_call" and step["tool_name"] == "sandbox_submit" for step in steps)

    @pytest.mark.asyncio
    async def test_email_analyzer_returns_playbook_friendly_aliases(self, tmp_path):
        sample_email = EmailMessage()
        sample_email["From"] = "Billing <billing@secure-payroll-check.com>"
        sample_email["To"] = "analyst@example.com"
        sample_email["Subject"] = "Invoice review"
        sample_email["Return-Path"] = "<bounce@secure-payroll-check.com>"
        sample_email["Message-ID"] = "<aisa-test@example.com>"
        sample_email["Received"] = "from 185.220.101.45 by mx.example.com with ESMTP id 12345;"
        sample_email.set_content("Please review https://secure-payroll-check.com/login immediately.")
        sample_email.add_attachment(
            b"dummy attachment bytes",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.docm",
        )

        eml_path = tmp_path / "sample.eml"
        eml_path.write_bytes(sample_email.as_bytes())

        analyzer = EmailAnalyzer({"analysis": {"enable_llm": False}})
        result = await analyzer.analyze(str(eml_path))

        assert "error" not in result
        assert result["analysis_type"] == "email"
        assert result["body"]
        assert result["sender_domain"] == "secure-payroll-check.com"
        assert result["sender_ip"] == "185.220.101.45"
        assert result["attachments"]
        assert result["attachments"][0]["path"]
        assert result["attachments"][0]["sha256"]
        assert result["attachments"][0]["type"] == "docm"


# ====================================================================== #
#  7. SandboxOrchestrator file routing
# ====================================================================== #

class TestSandboxOrchestrator:
    """Test SandboxOrchestrator.select_sandbox() file routing.

    All tests use temporary files -- no real malware is involved.
    Docker and subprocess calls are NOT made.
    """

    def test_select_sandbox_exe(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "windows_pe"
        assert "remnux/flare" in result["image"]

    def test_select_sandbox_dll(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.dll"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "windows_pe"

    def test_select_sandbox_elf(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "linux_elf"
        assert "remnux" in result["image"]

    def test_select_sandbox_apk(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.apk"
        f.write_bytes(b"PK" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "android_apk"

    def test_select_sandbox_doc_local_static(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.doc"
        f.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "local_static"
        assert result["profile"] == "office_macro"

    def test_select_sandbox_pdf_local_static(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.pdf"
        f.write_bytes(b"%PDF-1.4" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "local_static"
        assert result["profile"] == "pdf_analysis"

    def test_select_sandbox_ps1_script(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.ps1"
        f.write_text("Write-Host 'test'")
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "script_analysis"

    def test_select_sandbox_js_script(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.js"
        f.write_text("console.log('test');")
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "script_analysis"

    def test_select_sandbox_jar(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.jar"
        f.write_bytes(b"PK" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "java_analysis"

    def test_select_sandbox_zip(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.zip"
        f.write_bytes(b"PK" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "docker"
        assert result["profile"] == "archive_analysis"

    def test_select_sandbox_unknown_extension_no_adapters(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.weird"
        f.write_bytes(b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert result["sandbox_type"] == "local_static"
        assert result["profile"] == "generic_static"

    def test_select_sandbox_unknown_extension_with_cloud_adapter(self, tmp_path):
        orch = SandboxOrchestrator(config={}, sandbox_adapters={"hybrid": MagicMock()})
        f = tmp_path / "sample.weird"
        f.write_bytes(b"\x00" * 100)
        result = orch.select_sandbox(str(f))
        assert result["sandbox_type"] == "cloud_api"
        assert result["cloud_adapter"] == "hybrid"

    def test_select_sandbox_file_not_found(self, sandbox_orchestrator):
        result = sandbox_orchestrator.select_sandbox("/nonexistent/path/file.exe")
        assert "error" in result

    def test_select_sandbox_empty_file(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "empty.exe"
        f.write_bytes(b"")
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert "error" in result

    def test_select_sandbox_file_too_large(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "huge.exe"
        # Create a sparse file that reports large size
        f.write_bytes(b"MZ" + b"\x00" * 10)
        # Patch stat to return large size
        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_size=200 * 1024 * 1024)
            result = sandbox_orchestrator.select_sandbox(str(f))
        assert "error" in result
        assert "too large" in result["error"]

    def test_select_sandbox_returns_file_hash(self, sandbox_orchestrator, tmp_path):
        f = tmp_path / "sample.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = sandbox_orchestrator.select_sandbox(str(f))
        assert "file_hash" in result
        assert len(result["file_hash"]) == 64  # SHA-256 hex

    @pytest.mark.asyncio
    async def test_submit_docker_mocked(self, sandbox_orchestrator, tmp_path):
        """Docker submission should be mocked -- no real Docker calls."""
        f = tmp_path / "sample.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"file output", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await sandbox_orchestrator.submit_to_sandbox(str(f))
        assert result.get("status") in ("completed", "submitted", "error")

    @pytest.mark.asyncio
    async def test_submit_local_static(self, sandbox_orchestrator, tmp_path):
        """Local static analysis should work without Docker."""
        f = tmp_path / "sample.pdf"
        f.write_bytes(b"%PDF-1.4\n/JavaScript /JS /OpenAction\n")
        result = await sandbox_orchestrator.submit_to_sandbox(str(f))
        assert result["sandbox_type"] == "local_static"
        assert result["status"] == "completed"

    def test_get_sandbox_status_empty(self, sandbox_orchestrator):
        status = sandbox_orchestrator.get_sandbox_status()
        assert isinstance(status, list)

    def test_get_sandbox_status_includes_local_backends(self, sandbox_orchestrator):
        status = sandbox_orchestrator.get_sandbox_status()
        ids = {item.get("id") for item in status}
        local_static = next(item for item in status if item.get("id") == "local_static")
        assert {"docker", "vm", "local_static", "cloud_api"}.issubset(ids)
        assert local_static["status"] == "available"

    def test_invalidate_cache(self, sandbox_orchestrator):
        sandbox_orchestrator._available_cache["docker"] = True
        sandbox_orchestrator.invalidate_cache()
        assert len(sandbox_orchestrator._available_cache) == 0


class TestSandboxIntegration:
    """Regression tests for sandbox lookup integrations."""

    @pytest.mark.asyncio
    async def test_anyrun_placeholder_does_not_claim_report_found(self):
        integration = SandboxIntegration(config={"api_keys": {}})

        result = await integration._check_anyrun("a" * 64)

        assert result["found"] is False
        assert result["status"] == "manual_lookup_required"
        assert "search_url" in result
        assert "manual" in result["note"].lower()

    def test_api_key_alias_supports_legacy_and_new_sandbox_names(self):
        integration = SandboxIntegration(config={"api_keys": {"joesandbox": "abc123", "hybridanalysis": "def456"}})

        assert integration._get_api_key("joe_sandbox", "joesandbox") == "abc123"
        assert integration._get_api_key("hybrid_analysis", "hybridanalysis") == "def456"


# ====================================================================== #
#  8. MCPClientManager
# ====================================================================== #

class TestMCPClientManager:
    """Test MCPClientManager connection status (no real connections)."""

    def test_initial_connection_status_empty(self, mcp_manager):
        assert mcp_manager.get_connection_status() == {}

    def test_is_connected_false_for_unknown(self, mcp_manager):
        assert mcp_manager.is_connected("nonexistent") is False

    def test_mcp_server_config_to_dict(self):
        cfg = MCPServerConfig(
            name="remnux",
            transport="stdio",
            command="remnux-server",
            args=["--verbose"],
            description="REMnux MCP",
            token="secret_token",
            auto_connect=True,
        )
        d = cfg.to_dict()
        assert d["name"] == "remnux"
        assert d["transport"] == "stdio"
        assert d["command"] == "remnux-server"
        assert d["args"] == ["--verbose"]
        assert d["auto_connect"] is True
        # Token should NOT be in the serialised dict
        assert "token" not in d

    def test_mcp_server_config_from_dict(self):
        d = {"name": "flare", "transport": "sse", "url": "http://localhost:8080", "auto_connect": True}
        cfg = MCPServerConfig.from_dict(d)
        assert cfg.name == "flare"
        assert cfg.transport == "sse"
        assert cfg.url == "http://localhost:8080"
        assert cfg.auto_connect is True

    def test_mcp_connection_defaults(self):
        cfg = MCPServerConfig(name="test", transport="stdio")
        conn = MCPConnection(config=cfg)
        assert conn.connected is False
        assert conn.tools == []
        assert conn.error is None

    @pytest.mark.asyncio
    async def test_list_tools_disconnected(self, mcp_manager):
        tools = await mcp_manager.list_tools("nonexistent")
        assert tools == []

    @pytest.mark.asyncio
    async def test_list_all_tools_empty(self, mcp_manager):
        result = await mcp_manager.list_all_tools()
        assert result == {}

    @pytest.mark.asyncio
    async def test_call_tool_unregistered_server(self, mcp_manager):
        result = await mcp_manager.call_tool("unknown", "tool", {})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_call_tool_disconnected_server(self, mcp_manager):
        cfg = MCPServerConfig(name="srv", transport="stdio")
        conn = MCPConnection(config=cfg, connected=False)
        mcp_manager._connections["srv"] = conn
        result = await mcp_manager.call_tool("srv", "tool", {})
        assert "error" in result
        assert "not connected" in result["error"]

    @pytest.mark.asyncio
    async def test_disconnect_all_noop(self, mcp_manager):
        """disconnect_all on empty manager should not raise."""
        await mcp_manager.disconnect_all()

    @pytest.mark.asyncio
    async def test_reconnect_unknown_server(self, mcp_manager):
        result = await mcp_manager.reconnect("nonexistent")
        assert result is False

    def test_persist_connection_preserves_existing_token_and_auto_connect(self, agent_store):
        manager = MCPClientManager(agent_store=agent_store)
        agent_store.save_mcp_connection(
            "persisted",
            "http",
            {
                "name": "persisted",
                "transport": "http",
                "url": "http://localhost:8080/mcp",
                "token": "top-secret",
                "auto_connect": True,
            },
        )
        conn = MCPConnection(
            config=MCPServerConfig(
                name="persisted",
                transport="http",
                url="http://localhost:8080/mcp",
                auto_connect=True,
            ),
            connected=True,
            tools=[{"name": "hunt"}],
        )
        manager._persist_connection("persisted", conn)

        saved = agent_store.list_mcp_connections()[0]
        assert saved["config_json"]["token"] == "top-secret"
        assert saved["config_json"]["auto_connect"] is True


# ====================================================================== #
#  9. FastAPI endpoint tests
# ====================================================================== #

class TestFastAPIEndpoints:
    """Test API routes via Starlette TestClient (synchronous)."""

    @staticmethod
    def _build_app(agent_store, tool_registry=None, mcp_client=None, playbook_engine=None):
        """Build a minimal FastAPI app with the agent routes mounted."""
        from fastapi import FastAPI
        from src.web.routes import agent as agent_routes
        from src.web.routes import playbooks as playbook_routes
        from src.web.routes import mcp_management as mcp_routes

        app = FastAPI()
        app.state.agent_loop = None
        app.state.agent_store = agent_store
        app.state.tool_registry = tool_registry
        app.state.mcp_client = mcp_client
        app.state.playbook_engine = playbook_engine

        app.include_router(agent_routes.router, prefix="/api/agent")
        app.include_router(playbook_routes.router, prefix="/api/playbooks")
        app.include_router(mcp_routes.router, prefix="/api/mcp")

        return app

    def test_get_agent_stats(self, agent_store, tool_registry):
        from starlette.testclient import TestClient

        agent_store.create_session(goal="Test")
        app = self._build_app(agent_store, tool_registry=tool_registry)
        client = TestClient(app)

        resp = client.get("/api/agent/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_sessions" in data
        assert data["total_sessions"] >= 1

    def test_get_agent_sessions(self, agent_store):
        from starlette.testclient import TestClient

        agent_store.create_session(goal="Session A")
        agent_store.create_session(goal="Session B")
        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.get("/api/agent/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["sessions"]) == 2

    def test_get_agent_sessions_with_status_filter(self, agent_store):
        from starlette.testclient import TestClient

        sid = agent_store.create_session(goal="Active")
        agent_store.create_session(goal="Will complete")
        agent_store.update_session_status(
            agent_store.list_sessions()[0]["id"], "completed"
        )
        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.get("/api/agent/sessions?status=active")
        assert resp.status_code == 200

    def test_get_agent_tools(self, agent_store, tool_registry):
        from starlette.testclient import TestClient

        async def noop(**kw):
            return {}
        tool_registry.register_local_tool("t1", "Tool 1", {}, "analysis", noop)
        app = self._build_app(agent_store, tool_registry=tool_registry)
        client = TestClient(app)

        resp = client.get("/api/agent/tools")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tools"]) == 1
        assert data["tools"][0]["name"] == "t1"

    def test_get_agent_tools_no_registry(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store, tool_registry=None)
        client = TestClient(app)

        resp = client.get("/api/agent/tools")
        assert resp.status_code == 503

    def test_get_playbooks_empty(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.get("/api/playbooks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["playbooks"] == []

    def test_get_playbooks_from_store(self, agent_store):
        from starlette.testclient import TestClient

        agent_store.save_playbook("PB1", "Desc", [{"name": "s", "tool": "t"}])
        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.get("/api/playbooks")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["playbooks"]) >= 1

    def test_get_playbooks_from_engine(self, agent_store, playbook_engine):
        from starlette.testclient import TestClient

        playbook_engine.register_playbook("Engine PB", "From engine", [{"name": "s", "tool": "t"}])
        app = self._build_app(agent_store, playbook_engine=playbook_engine)
        client = TestClient(app)

        resp = client.get("/api/playbooks")
        assert resp.status_code == 200
        names = [p["name"] for p in resp.json()["playbooks"]]
        assert "Engine PB" in names

    def test_get_playbook_details_include_input_parameters(self, agent_store, playbook_engine):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store, playbook_engine=playbook_engine)
        client = TestClient(app)

        resp = client.get("/api/playbooks/alert_triage")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data.get("input_params"), list)
        assert "alert_text" in data.get("parameters", {})

    def test_run_playbook_accepts_raw_params_payload(self, agent_store, playbook_engine):
        from starlette.testclient import TestClient

        pid = playbook_engine.register_playbook(
            "Route PB",
            "Route payload compatibility",
            [{"name": "step1", "tool": "investigate_ioc", "params": {"ioc": "{{ioc}}"}}],
        )
        app = self._build_app(agent_store, playbook_engine=playbook_engine)
        client = TestClient(app)

        resp = client.post(f"/api/playbooks/{pid}/run", json={"ioc": "1.2.3.4"})
        assert resp.status_code == 200
        session_id = resp.json()["session_id"]
        steps = []
        for _ in range(50):
            steps = agent_store.get_steps(session_id)
            if steps:
                break
            time.sleep(0.02)
        assert steps
        assert '"ioc": "1.2.3.4"' in steps[0]["tool_params"]

    def test_get_mcp_servers_empty(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.get("/api/mcp/servers")
        assert resp.status_code == 200
        data = resp.json()
        assert data["servers"] == []

    def test_add_and_list_mcp_servers(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.post("/api/mcp/servers", json={
            "name": "test-server",
            "transport": "stdio",
            "command": "test-cmd",
        })
        assert resp.status_code == 200
        assert resp.json()["name"] == "test-server"

        resp2 = client.get("/api/mcp/servers")
        assert resp2.status_code == 200
        assert len(resp2.json()["servers"]) == 1

    def test_add_mcp_server_persists_auto_connect(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.post("/api/mcp/servers", json={
            "name": "auto-server",
            "transport": "stdio",
            "command": "test-cmd",
            "auto_connect": True,
        })
        assert resp.status_code == 200

        saved = agent_store.list_mcp_connections()[0]
        assert saved["config_json"]["auto_connect"] is True

    def test_mcp_server_list_masks_secret_env_and_token(self, agent_store):
        from starlette.testclient import TestClient

        agent_store.save_mcp_connection(
            "secret-server",
            "http",
            {
                "name": "secret-server",
                "transport": "http",
                "url": "http://localhost:8080/mcp",
                "token": "very-secret-token-123456",
                "env": {"API_KEY": "another-secret-987654"},
            },
        )
        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.get("/api/mcp/servers")
        assert resp.status_code == 200
        server = next(s for s in resp.json()["servers"] if s["name"] == "secret-server")
        assert "*" in server["config_json"]["token"]
        assert "*" in server["config_json"]["env"]["API_KEY"]

    def test_connect_added_mcp_server_registers_tools_for_agent(self, agent_store):
        from starlette.testclient import TestClient

        class FakeMCPClient:
            async def connect(self, cfg):
                return True

            async def list_tools(self, server_name):
                return [{
                    "name": "echo_lookup",
                    "description": "Echo lookup",
                    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                }]

            def get_connection_status(self):
                return {"user-mcp": {"connected": True, "tool_count": 1}}

        tool_registry = ToolRegistry()
        app = self._build_app(agent_store, tool_registry=tool_registry, mcp_client=FakeMCPClient())
        client = TestClient(app)

        add_resp = client.post("/api/mcp/servers", json={
            "name": "user-mcp",
            "transport": "stdio",
            "command": "python",
            "args": ["-m", "src.mcp_servers.osint_tools"],
        })
        assert add_resp.status_code == 200

        connect_resp = client.post("/api/mcp/servers/user-mcp/connect")
        assert connect_resp.status_code == 200

        tools_resp = client.get("/api/agent/tools")
        assert tools_resp.status_code == 200
        names = [t["name"] for t in tools_resp.json()["tools"]]
        assert "user-mcp.echo_lookup" in names

    def test_delete_mcp_server(self, agent_store):
        from starlette.testclient import TestClient

        agent_store.save_mcp_connection("to-delete", "stdio", {})
        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.delete("/api/mcp/servers/to-delete")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

        resp2 = client.get("/api/mcp/servers")
        assert len(resp2.json()["servers"]) == 0

    def test_delete_connected_mcp_server_disconnects_and_unregisters(self, agent_store):
        from starlette.testclient import TestClient

        class FakeMCPClient:
            def __init__(self):
                self.disconnected = []

            async def disconnect(self, server_name):
                self.disconnected.append(server_name)

        class FakeToolRegistry:
            def __init__(self):
                self.unregistered = []

            def unregister_server(self, server_name):
                self.unregistered.append(server_name)
                return 1

        agent_store.save_mcp_connection(
            "user-mcp",
            "stdio",
            {"name": "user-mcp", "transport": "stdio", "command": "python", "auto_connect": True},
        )
        mcp_client = FakeMCPClient()
        tool_registry = FakeToolRegistry()
        app = self._build_app(agent_store, tool_registry=tool_registry, mcp_client=mcp_client)
        client = TestClient(app)

        resp = client.delete("/api/mcp/servers/user-mcp")
        assert resp.status_code == 200
        assert mcp_client.disconnected == ["user-mcp"]
        assert tool_registry.unregistered == ["user-mcp"]
        assert agent_store.list_mcp_connections() == []

    def test_delete_config_managed_mcp_server_is_rejected(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store)
        app.state.config = {
            "mcp_servers": [
                {"name": "built-in", "transport": "stdio", "command": "python", "auto_connect": True}
            ]
        }
        client = TestClient(app)

        resp = client.delete("/api/mcp/servers/built-in")
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_auto_connect_mcp_servers_uses_db_backed_auto_connect(self, tmp_path):
        from src.agent.agent_store import AgentStore
        from src.web.app import _auto_connect_mcp_servers

        class DummyMCPClient:
            def __init__(self):
                self.connected = []

            async def connect(self, cfg):
                self.connected.append(cfg)
                return True

            async def list_tools(self, server_name):
                return [{"name": "hunt"}]

        class DummyToolRegistry:
            def __init__(self):
                self.registered = []

            def register_mcp_tools(self, server_name, tools):
                self.registered.append((server_name, tools))

        store = AgentStore(db_path=str(tmp_path / "agent.db"))
        store.save_mcp_connection(
            "db-only",
            "stdio",
            {
                "name": "db-only",
                "transport": "stdio",
                "command": "python",
                "args": ["-m", "src.mcp_servers.free_osint_tools"],
                "auto_connect": True,
            },
        )
        app = SimpleNamespace(
            state=SimpleNamespace(
                mcp_client=DummyMCPClient(),
                tool_registry=DummyToolRegistry(),
                agent_store=store,
                config={"mcp_servers": []},
            )
        )

        await _auto_connect_mcp_servers(app)

        assert len(app.state.mcp_client.connected) == 1
        assert app.state.mcp_client.connected[0].name == "db-only"
        assert app.state.tool_registry.registered == [("db-only", [{"name": "hunt"}])]

    @pytest.mark.asyncio
    async def test_auto_connect_mcp_servers_treats_legacy_user_server_as_startup_managed(self, tmp_path):
        from src.agent.agent_store import AgentStore
        from src.web.app import _auto_connect_mcp_servers

        class DummyMCPClient:
            def __init__(self):
                self.connected = []

            async def connect(self, cfg):
                self.connected.append(cfg)
                return True

            async def list_tools(self, server_name):
                return []

        class DummyToolRegistry:
            def register_mcp_tools(self, server_name, tools):
                return None

        store = AgentStore(db_path=str(tmp_path / "agent.db"))
        store.save_mcp_connection(
            "legacy-user-server",
            "stdio",
            {
                "name": "legacy-user-server",
                "transport": "stdio",
                "command": "python",
                "args": ["-m", "src.mcp_servers.free_osint_tools"],
            },
        )
        app = SimpleNamespace(
            state=SimpleNamespace(
                mcp_client=DummyMCPClient(),
                tool_registry=DummyToolRegistry(),
                agent_store=store,
                config={"mcp_servers": []},
            )
        )

        await _auto_connect_mcp_servers(app)

        assert [cfg.name for cfg in app.state.mcp_client.connected] == ["legacy-user-server"]

    @pytest.mark.asyncio
    async def test_auto_connect_mcp_servers_prefers_config_flag_over_stale_db_snapshot(self, tmp_path):
        from src.agent.agent_store import AgentStore
        from src.web.app import _auto_connect_mcp_servers

        class DummyMCPClient:
            def __init__(self):
                self.connected = []

            async def connect(self, cfg):
                self.connected.append(cfg)
                return True

            async def list_tools(self, server_name):
                return []

        class DummyToolRegistry:
            def register_mcp_tools(self, server_name, tools):
                return None

        store = AgentStore(db_path=str(tmp_path / "agent.db"))
        store.save_mcp_connection(
            "cfg-server",
            "stdio",
            {
                "name": "cfg-server",
                "transport": "stdio",
                "command": "python",
                "auto_connect": False,
            },
        )
        app = SimpleNamespace(
            state=SimpleNamespace(
                mcp_client=DummyMCPClient(),
                tool_registry=DummyToolRegistry(),
                agent_store=store,
                config={
                    "mcp_servers": [
                        {
                            "name": "cfg-server",
                            "transport": "stdio",
                            "command": "python",
                            "auto_connect": True,
                        }
                    ]
                },
            )
        )

        await _auto_connect_mcp_servers(app)

        assert [cfg.name for cfg in app.state.mcp_client.connected] == ["cfg-server"]

    def test_agent_stats_with_mcp(self, agent_store, tool_registry, mcp_manager):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store, tool_registry=tool_registry, mcp_client=mcp_manager)
        client = TestClient(app)

        resp = client.get("/api/agent/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "mcp_servers" in data
        assert data["mcp_servers"] == 0

    def test_investigate_without_agent_loop(self, agent_store):
        from starlette.testclient import TestClient

        app = self._build_app(agent_store)
        client = TestClient(app)

        resp = client.post("/api/agent/investigate", json={"goal": "test"})
        assert resp.status_code == 503


# ====================================================================== #
#  10. New tools: sandbox_submit, correlate_findings, recall_ioc
# ====================================================================== #

class TestNewAgentTools:
    """Test the three new tools registered by register_default_tools()."""

    def test_register_default_tools_includes_new_tools(self, tool_registry):
        tool_registry.register_default_tools({})
        names = [t.name for t in tool_registry.list_tools()]
        assert "sandbox_submit" in names
        assert "correlate_findings" in names

    @pytest.mark.asyncio
    async def test_extract_iocs_tool_returns_playbook_friendly_contract(self, tool_registry):
        tool_registry.register_default_tools({})
        result = await tool_registry.execute_local_tool(
            "extract_iocs",
            text="From bad@evil.com visit http://evil.com on 8.8.8.8 CVE-2024-1234 and inspect C:\\Temp\\evil.exe",
        )
        assert "error" not in result
        assert "ips" in result
        assert "sender_domains" in result
        assert "all_iocs" in result
        assert "cve_ids" in result
        assert "file_paths" in result
        assert "executables" in result
        assert "evil.com" in result["sender_domains"]

    @pytest.mark.asyncio
    async def test_correlate_findings_tool_accepts_structured_inputs(self, tool_registry):
        tool_registry.register_default_tools({})
        result = await tool_registry.execute_local_tool(
            "correlate_findings",
            hunt_results={"summary": "phishing beacon to evil.com"},
            threat_intel={"verdict": "suspicious", "ioc": "evil.com"},
        )
        assert "error" not in result
        assert "statistics" in result

    def test_sandbox_submit_is_dangerous(self, tool_registry):
        tool_registry.register_default_tools({})
        td = tool_registry.get_tool("sandbox_submit")
        assert td is not None
        assert td.is_dangerous is True
        assert td.requires_approval is True
        assert td.category == "sandbox"

    def test_correlate_findings_category(self, tool_registry):
        tool_registry.register_default_tools({})
        td = tool_registry.get_tool("correlate_findings")
        assert td is not None
        assert td.category == "analysis"

    def test_recall_ioc_category(self, tool_registry):
        tool_registry.register_default_tools({})
        td = tool_registry.get_tool("recall_ioc")
        assert td is not None
        assert td.category == "analysis"

    def test_remediation_tools_require_approval(self, tool_registry):
        tool_registry.register_default_tools({})
        for tool_name in ("isolate_device", "block_ip", "quarantine_file"):
            td = tool_registry.get_tool(tool_name)
            assert td is not None
            assert td.requires_approval is True
            assert td.is_dangerous is True

    @pytest.mark.asyncio
    async def test_correlate_findings_execution(self, tool_registry):
        tool_registry.register_default_tools({})
        result = await tool_registry.execute_local_tool(
            "correlate_findings", findings_text="powershell -enc base64"
        )
        # Should return correlation results or at least not error fatally
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_recall_ioc_execution_no_cache(self, tool_registry):
        tool_registry.register_default_tools({})
        result = await tool_registry.execute_local_tool("recall_ioc", ioc="1.2.3.4")
        assert isinstance(result, dict)
        assert result.get("cached") is False

    @pytest.mark.asyncio
    async def test_search_threat_intel_accepts_hypothesis_and_indicators(self, tool_registry):
        mock_ioc = MagicMock()
        mock_ioc.investigate = AsyncMock(return_value={"verdict": "SUSPICIOUS", "found": True})
        tool_registry.register_default_tools({}, ioc_investigator=mock_ioc)

        result = await tool_registry.execute_local_tool(
            "search_threat_intel",
            hypothesis="Possible C2 beaconing from finance workstation",
            indicators={"ips": ["185.220.101.45"], "domains": ["evil.example"]},
        )

        assert result["results_count"] >= 2
        assert "185.220.101.45" in result["searched_terms"]
        assert result["flagged_results"] >= 1

    @pytest.mark.asyncio
    async def test_recall_ioc_accepts_text_and_known_indicators(self, tool_registry):
        tool_registry.register_default_tools({})
        result = await tool_registry.execute_local_tool(
            "recall_ioc",
            text="Visit evil.com from 185.220.101.45",
            known_indicators={"hashes": ["44d88612fea8a8f36de82e1278abb02f4fc66b0c5d7d5e8f4c4c286f4a9f0f12"]},
        )

        assert "185.220.101.45" in result["requested_iocs"]
        assert "evil.com" in result["requested_iocs"]

    def test_total_tool_count_no_instances(self, tool_registry):
        """Without analyzer instances, should still expose all non-analyzer playbook helpers."""
        tool_registry.register_default_tools({})
        count = len(tool_registry.list_tools())
        assert count == 10

    def test_total_tool_count_with_mock_instances(self, tool_registry):
        """With analyzer instances, should expose the full local playbook toolset."""
        mock_ioc = MagicMock()
        mock_ioc.investigate = AsyncMock(return_value={"score": 50})
        mock_mal = MagicMock()
        mock_mal.analyze = AsyncMock(return_value={"type": "PE"})
        mock_email = MagicMock()
        mock_email.analyze = AsyncMock(return_value={"subject": "test"})

        tool_registry.register_default_tools(
            {},
            ioc_investigator=mock_ioc,
            malware_analyzer=mock_mal,
            email_analyzer=mock_email,
        )
        count = len(tool_registry.list_tools())
        assert count == 14


# ====================================================================== #
#  11. Settings API endpoints
# ====================================================================== #

class TestSettingsAPI:
    """Test GET/POST /api/config/settings."""

    def test_get_settings(self):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/config/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert "llm" in data

    def test_post_settings(self, tmp_path):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        client = TestClient(app)
        resp = client.post("/api/config/settings", json={
            "agent": {"max_steps": 100},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "saved"
        assert "live runtime" in data.get("message", "").lower()

    def test_post_settings_refreshes_live_runtime_api_keys_and_agent_provider(self):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        client = TestClient(app)
        resp = client.post("/api/config/settings", json={
            "llm": {
                "provider": "groq",
                "groq_endpoint": "https://api.groq.com/openai/v1",
                "groq_model": "openai/gpt-oss-20b",
            },
            "api_keys": {
                "virustotal": "vt-live-12345678",
                "groq": "gsk-live-12345678",
                "abusech": "abusech-live-12345678",
            },
        })
        assert resp.status_code == 200
        assert app.state.ioc_investigator.threat_intel.api_keys["virustotal"] == "vt-live-12345678"
        assert app.state.malware_analyzer.threat_intel.api_keys["virustotal"] == "vt-live-12345678"
        assert app.state.agent_loop.groq_key == "gsk-live-12345678"

        ti_server = next(s for s in app.state.config["mcp_servers"] if s["name"] == "threat-intel-free")
        assert ti_server["env"]["ABUSECH_AUTH_KEY"] == "abusech-live-12345678"

    def test_post_settings_can_clear_api_key_and_runtime_bridge(self):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        client = TestClient(app)

        seed_resp = client.post("/api/config/settings", json={
            "api_keys": {
                "abusech": "abusech-live-12345678",
            },
        })
        assert seed_resp.status_code == 200
        assert app.state.config["api_keys"]["abusech"] == "abusech-live-12345678"

        clear_resp = client.post("/api/config/settings", json={
            "api_keys": {
                "abusech": "",
            },
        })
        assert clear_resp.status_code == 200
        assert app.state.config["api_keys"]["abusech"] == ""

        ti_server = next(s for s in app.state.config["mcp_servers"] if s["name"] == "threat-intel-free")
        assert ti_server["env"]["ABUSECH_AUTH_KEY"] == ""

    def test_get_settings_masks_api_keys(self):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/config/settings")
        data = resp.json()
        # API keys should be masked (if any are configured)
        if "api_keys" in data:
            for key, val in data["api_keys"].items():
                if val and isinstance(val, str) and len(val) > 8:
                    assert "*" in val

    def test_llm_health_reports_active_groq_provider(self):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        app.state.config = {
            **app.state.config,
            'llm': {
                'provider': 'groq',
                'groq_endpoint': 'https://api.groq.com/openai/v1',
                'groq_model': 'openai/gpt-oss-20b',
            },
            'api_keys': {
                **app.state.config.get('api_keys', {}),
                'groq': 'gsk-test-key',
            },
        }
        app.state.web_provider.config = app.state.config

        client = TestClient(app)
        resp = client.get("/api/config/llm-health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "groq"
        assert data["available"] is True
        assert data["configured_model"] == "openai/gpt-oss-20b"

    def test_legacy_ollama_health_endpoint_is_provider_aware(self):
        from starlette.testclient import TestClient
        from src.web.app import create_app

        app = create_app()
        app.state.config = {
            **app.state.config,
            'llm': {
                'provider': 'groq',
                'groq_endpoint': 'https://api.groq.com/openai/v1',
                'groq_model': 'openai/gpt-oss-20b',
            },
            'api_keys': {
                **app.state.config.get('api_keys', {}),
                'groq': 'gsk-test-key',
            },
        }
        app.state.web_provider.config = app.state.config

        client = TestClient(app)
        resp = client.get("/api/config/ollama-health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "groq"
        assert data["available"] is True
        assert data["ollama_running"] is None


# ====================================================================== #
#  12. Full app component wiring
# ====================================================================== #

class TestAppComponentWiring:
    """Verify that create_app initializes all agent components."""

    def test_all_components_initialized(self):
        from src.web.app import create_app

        app = create_app()
        assert app.state.tool_registry is not None
        assert app.state.agent_store is not None
        assert app.state.agent_loop is not None
        assert app.state.mcp_client is not None
        assert app.state.playbook_engine is not None
        assert app.state.correlation_engine is not None
        assert app.state.investigation_memory is not None
        assert app.state.sandbox_orchestrator is not None

    def test_tool_instances_initialized(self):
        from src.web.app import create_app

        app = create_app()
        assert app.state.ioc_investigator is not None
        assert app.state.malware_analyzer is not None
        assert app.state.email_analyzer is not None

    def test_full_tool_count(self):
        from src.web.app import create_app

        app = create_app()
        tools = app.state.tool_registry.list_tools()
        assert len(tools) == 14

    def test_cross_tool_wiring(self):
        from src.web.app import create_app

        app = create_app()
        # EmailAnalyzer should have cross-references
        email = app.state.email_analyzer
        assert email.ioc_investigator is not None
        assert email.file_analyzer is not None
        # MalwareAnalyzer should have IOC investigator
        mal = app.state.malware_analyzer
        assert mal.ioc_investigator is not None


# ====================================================================== #
#  TestAgentLoop
# ====================================================================== #

from src.agent.agent_loop import AgentLoop


def _make_agent_loop(tmp_path, **overrides):
    """Helper: build an AgentLoop with mocked dependencies."""
    db = tmp_path / "loop_test.db"
    store = AgentStore(db_path=str(db))
    registry = ToolRegistry()
    config = {
        "agent": {"max_steps": 5},
        "llm": {
            "provider": "ollama",
            "ollama_endpoint": "http://localhost:11434",
            "ollama_model": "llama3.1:8b",
            "groq_endpoint": "https://api.groq.com/openai/v1",
            "groq_model": "openai/gpt-oss-20b",
            "anthropic_model": "claude-sonnet-4-20250514",
        },
        "api_keys": {"anthropic": "", "groq": ""},
    }
    config.update(overrides.get("config_overrides", {}))
    return AgentLoop(
        config=config,
        tool_registry=registry,
        agent_store=store,
        llm_analyzer=overrides.get("llm_analyzer"),
        mcp_client=overrides.get("mcp_client"),
    )


class TestAgentLoop:
    """Tests for agent_loop.AgentLoop."""

    # ---- investigate creates session --------------------------------- #
    @pytest.mark.asyncio
    async def test_investigate_creates_session(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        # Patch _run_loop so the background thread does nothing
        with patch.object(loop, "_run_loop", new_callable=AsyncMock):
            session_id = await loop.investigate("Test goal")
        assert isinstance(session_id, str) and len(session_id) > 0
        assert session_id in loop._active_sessions

    # ---- get_state returns None for unknown session ------------------ #
    def test_get_state_returns_none_for_unknown(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        assert loop.get_state("nonexistent") is None

    # ---- get_state returns state dict for active session ------------- #
    def test_get_state_returns_state_for_active(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="test")
        loop._active_sessions["s1"] = state
        result = loop.get_state("s1")
        assert result is not None
        assert result["session_id"] == "s1"
        assert result["goal"] == "test"


    # ---- subscribe returns a queue ----------------------------------- #
    def test_subscribe_returns_queue(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        q = loop.subscribe("s1")
        assert isinstance(q, asyncio.Queue)
        assert q in loop._subscribers["s1"]

    # ---- unsubscribe removes queue ----------------------------------- #
    def test_unsubscribe_removes_queue(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        q = loop.subscribe("s1")
        loop.unsubscribe("s1", q)
        assert q not in loop._subscribers.get("s1", [])

    # ---- _notify sends to all subscribers ---------------------------- #
    def test_notify_sends_to_subscribers(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        q1 = loop.subscribe("s1")
        q2 = loop.subscribe("s1")
        loop._notify("s1", {"type": "test"})
        assert q1.get_nowait() == {"type": "test"}
        assert q2.get_nowait() == {"type": "test"}

    # ---- approve_action sets the event ------------------------------- #
    @pytest.mark.asyncio
    async def test_approve_action_sets_event(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="test")
        state.request_approval({"tool": "x"}, "reason")
        loop._active_sessions["s1"] = state
        loop._approval_events["s1"] = asyncio.Event()

        result = await loop.approve_action("s1")
        assert result is True
        assert state.pending_approval["approved"] is True
        assert loop._approval_events["s1"].is_set()

    # ---- reject_action sets the event -------------------------------- #
    @pytest.mark.asyncio
    async def test_reject_action_sets_event(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="test")
        state.request_approval({"tool": "x"}, "reason")
        loop._active_sessions["s1"] = state
        loop._approval_events["s1"] = asyncio.Event()

        result = await loop.reject_action("s1")
        assert result is True
        assert state.pending_approval["approved"] is False

    # ---- approve returns False when no pending approval -------------- #
    @pytest.mark.asyncio
    async def test_approve_action_no_pending(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        assert await loop.approve_action("nonexistent") is False

    # ---- cancel_session updates status ------------------------------- #
    @pytest.mark.asyncio
    async def test_cancel_session_updates_status(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="test")
        state.transition(AgentPhase.THINKING)
        loop._active_sessions["s1"] = state
        loop._approval_events["s1"] = asyncio.Event()
        # create a session row in the store first
        loop.store.create_session(goal="test")

        await loop.cancel_session("s1")
        assert state.phase == AgentPhase.FAILED
        assert "Cancelled by analyst" in state.errors

    # ---- run_tool executes a local tool ------------------------------ #
    @pytest.mark.asyncio
    async def test_run_tool_executes_local_tool(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        async def dummy_executor(**kwargs):
            return {"status": "ok"}
        loop.tools.register_local_tool(
            name="dummy_tool",
            description="A test tool",
            parameters={"properties": {}},
            category="test",
            executor=dummy_executor,
        )
        result = await loop.run_tool("dummy_tool", {})
        assert result == {"status": "ok"}

    # ---- run_tool returns error for unknown tool --------------------- #
    @pytest.mark.asyncio
    async def test_run_tool_returns_error_for_unknown(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        result = await loop.run_tool("no_such_tool", {})
        assert "error" in result
        assert "not found" in result["error"].lower()

    # ---- _extract_json from plain JSON ------------------------------- #
    def test_extract_json_plain(self):
        text = '{"action": "final_answer", "answer": "done"}'
        result = AgentLoop._extract_json(text)
        assert result == {"action": "final_answer", "answer": "done"}

    # ---- _extract_json from markdown code block ---------------------- #
    def test_extract_json_from_markdown(self):
        text = 'Some text\n```json\n{"action": "use_tool", "tool": "scan"}\n```\nmore text'
        result = AgentLoop._extract_json(text)
        assert result is not None
        assert result["action"] == "use_tool"

    # ---- _extract_json returns None for empty input ------------------ #
    def test_extract_json_empty(self):
        assert AgentLoop._extract_json("") is None
        assert AgentLoop._extract_json(None) is None

    # ---- _think calls LLM ------------------------------------------- #
    @pytest.mark.asyncio
    async def test_think_calls_llm(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="investigate malware")
        state.transition(AgentPhase.THINKING)

        mock_response = '{"action": "final_answer", "answer": "clean", "verdict": "CLEAN"}'
        with patch.object(loop, "_chat_with_tools", new_callable=AsyncMock, return_value=mock_response):
            decision = await loop._think(state)
        assert decision is not None
        # When findings are empty, final_answer is auto-dispatched to use_tool
        assert decision["action"] in ("final_answer", "use_tool")

    @pytest.mark.asyncio
    async def test_think_final_answer_after_findings(self, tmp_path):
        """LLM final_answer is accepted when findings already exist."""
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="investigate malware")
        state.transition(AgentPhase.THINKING)
        state.add_finding({"type": "tool_result", "tool": "test", "result": {}})

        mock_response = '{"action": "final_answer", "answer": "clean", "verdict": "CLEAN"}'
        with patch.object(loop, "_chat_with_tools", new_callable=AsyncMock, return_value=mock_response):
            decision = await loop._think(state)
        assert decision is not None
        assert decision["action"] == "final_answer"

    # ---- _act records step ------------------------------------------- #
    @pytest.mark.asyncio
    async def test_act_records_step(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        sid = loop.store.create_session(goal="test act")
        state = AgentState(session_id=sid, goal="test act")
        state.transition(AgentPhase.THINKING)
        state.transition(AgentPhase.ACTING)

        async def scan_executor(**kwargs):
            return {"clean": True}
        loop.tools.register_local_tool(
            name="scan_ip",
            description="Scan an IP",
            parameters={"properties": {"ip": {"type": "string"}}},
            category="test",
            executor=scan_executor,
        )

        decision = {"action": "use_tool", "tool": "scan_ip", "params": {"ip": "1.2.3.4"}}
        result = await loop._act(state, decision)
        assert result == {"clean": True}

    # ---- _generate_summary with final_answer finding ----------------- #
    @pytest.mark.asyncio
    async def test_generate_summary(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="test")
        state.add_finding({"type": "final_answer", "answer": "All clear", "verdict": "CLEAN"})
        summary = await loop._generate_summary(state)
        assert "CLEAN" in summary
        assert "All clear" in summary

    # ---- _generate_summary fallback when LLM fails ------------------- #
    @pytest.mark.asyncio
    async def test_generate_summary_fallback(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        state = AgentState(session_id="s1", goal="test")
        state.step_count = 3
        state.add_finding({"type": "tool_result", "tool": "scan", "result": {}})
        with patch.object(loop, "_call_llm_text", new_callable=AsyncMock, return_value=None):
            summary = await loop._generate_summary(state)
        assert "3 steps" in summary

    # ---- Ollama provider config -------------------------------------- #
    def test_ollama_provider_config(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        assert loop.provider == "ollama"
        assert loop.ollama_model == "llama3.1:8b"
        assert "11434" in loop.ollama_endpoint

    # ---- Anthropic provider config ----------------------------------- #
    def test_anthropic_provider_config(self, tmp_path):
        loop = _make_agent_loop(
            tmp_path,
            config_overrides={
                "llm": {
                    "provider": "anthropic",
                    "anthropic_model": "claude-sonnet-4-20250514",
                },
                "api_keys": {"anthropic": "sk-test-key"},
            },
        )
        assert loop.provider == "anthropic"
        assert loop.anthropic_key == "sk-test-key"
        assert loop.anthropic_model == "claude-sonnet-4-20250514"

    # ---- Groq provider config ---------------------------------------- #
    def test_groq_provider_config(self, tmp_path):
        loop = _make_agent_loop(
            tmp_path,
            config_overrides={
                "llm": {
                    "provider": "groq",
                    "groq_endpoint": "https://api.groq.com/openai/v1",
                    "groq_model": "openai/gpt-oss-20b",
                },
                "api_keys": {"groq": "gsk-test-key", "anthropic": ""},
            },
        )
        assert loop.provider == "groq"
        assert loop.groq_key == "gsk-test-key"
        assert loop.groq_model == "openai/gpt-oss-20b"
        assert loop.groq_endpoint == "https://api.groq.com/openai/v1"

    # ---- _parse_tool_call_response ----------------------------------- #
    def test_parse_tool_call_response(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        raw = {
            "tool_calls": [{
                "function": {
                    "name": "scan_ip",
                    "arguments": {"ip": "10.0.0.1"},
                }
            }]
        }
        result = loop._parse_tool_call_response(raw)
        assert result["action"] == "use_tool"
        assert result["tool"] == "scan_ip"
        assert result["params"] == {"ip": "10.0.0.1"}

    def test_parse_openai_compatible_tool_call_response(self, tmp_path):
        loop = _make_agent_loop(tmp_path)
        raw = {
            "tool_calls": [{
                "function": {
                    "name": "investigate_ioc",
                    "arguments": "{\"ioc\": \"8.8.8.8\"}",
                }
            }]
        }
        result = loop._parse_tool_call_response(raw)
        assert result["action"] == "use_tool"
        assert result["tool"] == "investigate_ioc"
        assert result["params"] == {"ioc": "8.8.8.8"}


# ====================================================================== #
#  TestSandboxAdapters
# ====================================================================== #

from src.agent.adapters.sandbox_adapter import (
    SandboxAdapter,
    CAPEv2Adapter,
    HybridAnalysisAdapter,
    ANYRUNAdapter,
)


def _mock_aiohttp_response(status=200, json_data=None, text_data=""):
    """Create a mock aiohttp response context manager."""
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=json_data or {})
    mock_resp.text = AsyncMock(return_value=text_data)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


def _mock_session(response_ctx):
    """Create a mock aiohttp.ClientSession whose post/get return the given response."""
    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=response_ctx)
    mock_session.get = MagicMock(return_value=response_ctx)

    session_ctx = AsyncMock()
    session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    session_ctx.__aexit__ = AsyncMock(return_value=False)
    return session_ctx


class TestSandboxAdapters:
    """Tests for sandbox_adapter.py adapters."""

    # ---- SandboxAdapter base is abstract ----------------------------- #
    @pytest.mark.asyncio
    async def test_sandbox_adapter_base_abstract(self):
        adapter = SandboxAdapter()
        with pytest.raises(NotImplementedError):
            await adapter.submit_file("/fake/path")
        with pytest.raises(NotImplementedError):
            await adapter.submit_url("http://example.com")
        with pytest.raises(NotImplementedError):
            await adapter.get_report("id123")
        # get_status has a default implementation
        status = await adapter.get_status("id123")
        assert status == "unknown"

    # ---- CAPEv2 init ------------------------------------------------ #
    def test_capev2_adapter_init(self):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000", api_key="testkey")
        assert adapter.name == "capev2"
        assert adapter.api_url == "http://cape.local:8000"
        assert adapter.api_key == "testkey"

    # ---- CAPEv2 submit_file ----------------------------------------- #
    @pytest.mark.asyncio
    async def test_capev2_submit_file(self, tmp_path):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000", api_key="key")
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"MZ fake binary content")

        resp_ctx = _mock_aiohttp_response(200, {"task_id": "42"})
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.submit_file(str(test_file))

        assert result["submission_id"] == "42"
        assert result["sandbox"] == "capev2"
        assert "sha256" in result

    # ---- CAPEv2 submit_file - file not found ------------------------- #
    @pytest.mark.asyncio
    async def test_capev2_submit_file_not_found(self):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000")
        result = await adapter.submit_file("/nonexistent/file.exe")
        assert "error" in result

    # ---- CAPEv2 get_report ------------------------------------------ #
    @pytest.mark.asyncio
    async def test_capev2_get_report(self):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000")
        report_data = {
            "info": {"score": 8, "duration": 120, "machine": {"name": "win10"}},
            "target": {"file": {"name": "mal.exe", "sha256": "abc123", "type": "PE32"}},
            "signatures": [{"name": "suspicious_api", "severity": 3, "description": "Uses API", "categories": [], "ttp": {}}],
            "network": {"dns": [], "http": [], "hosts": [], "domains": []},
            "behavior": {"processes": [{"pid": 1}]},
        }
        resp_ctx = _mock_aiohttp_response(200, report_data)
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.get_report("42")

        assert result["task_id"] == "42"
        assert result["score"] == 8
        assert result["process_count"] == 1
        assert len(result["signatures"]) == 1

    # ---- CAPEv2 get_status ------------------------------------------ #
    @pytest.mark.asyncio
    async def test_capev2_get_status(self):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000")
        resp_ctx = _mock_aiohttp_response(200, {"status": "reported"})
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            status = await adapter.get_status("42")
        assert status == "completed"

    # ---- HybridAnalysis init ---------------------------------------- #
    def test_hybrid_analysis_init(self):
        adapter = HybridAnalysisAdapter(api_key="ha-key")
        assert adapter.name == "hybrid_analysis"
        assert adapter.api_key == "ha-key"
        assert "hybrid-analysis.com" in adapter.api_url

    # ---- HybridAnalysis submit_file --------------------------------- #
    @pytest.mark.asyncio
    async def test_hybrid_submit_file(self, tmp_path):
        adapter = HybridAnalysisAdapter(api_key="ha-key")
        test_file = tmp_path / "sample.dll"
        test_file.write_bytes(b"MZ fake dll")

        resp_ctx = _mock_aiohttp_response(200, {"job_id": "j100", "sha256": "def456"})
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.submit_file(str(test_file))

        assert result["submission_id"] == "j100"
        assert result["sandbox"] == "hybrid_analysis"

    # ---- HybridAnalysis get_report ---------------------------------- #
    @pytest.mark.asyncio
    async def test_hybrid_get_report(self):
        adapter = HybridAnalysisAdapter(api_key="ha-key")
        report_data = {
            "verdict": "malicious",
            "threat_score": 95,
            "threat_level": 2,
            "vx_family": "Emotet",
            "tags": ["trojan"],
            "mitre_attcks": [{"tactic": "execution"}],
            "domains": ["evil.com"],
            "hosts": ["1.2.3.4"],
            "type": "PE32",
            "sha256": "abc",
        }
        resp_ctx = _mock_aiohttp_response(200, report_data)
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.get_report("j100")

        assert result["verdict"] == "malicious"
        assert result["threat_score"] == 95
        assert result["malware_family"] == "Emotet"

    # ---- HybridAnalysis search_hash --------------------------------- #
    @pytest.mark.asyncio
    async def test_hybrid_search_hash(self):
        adapter = HybridAnalysisAdapter(api_key="ha-key")
        search_data = [
            {"verdict": "malicious", "threat_score": 90, "vx_family": "TrickBot", "analysis_start_time": "2024-01-01"}
        ]
        resp_ctx = _mock_aiohttp_response(200, search_data)
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.search_hash("abc123hash")

        assert result["found"] is True
        assert result["verdict"] == "malicious"
        assert result["total_reports"] == 1

    # ---- HybridAnalysis search_hash not found ------------------------ #
    @pytest.mark.asyncio
    async def test_hybrid_search_hash_not_found(self):
        adapter = HybridAnalysisAdapter(api_key="ha-key")
        resp_ctx = _mock_aiohttp_response(200, [])
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.search_hash("unknownhash")
        assert result["found"] is False

    # ---- ANYRUN init ------------------------------------------------ #
    def test_anyrun_init(self):
        adapter = ANYRUNAdapter(api_key="ar-key")
        assert adapter.name == "anyrun"
        assert adapter.api_key == "ar-key"
        assert "any.run" in adapter.api_url

    # ---- ANYRUN submit_file ----------------------------------------- #
    @pytest.mark.asyncio
    async def test_anyrun_submit_file(self, tmp_path):
        adapter = ANYRUNAdapter(api_key="ar-key")
        test_file = tmp_path / "payload.bin"
        test_file.write_bytes(b"\x00\x01\x02 binary payload")

        resp_ctx = _mock_aiohttp_response(200, {"data": {"taskid": "t999"}})
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.submit_file(str(test_file))

        assert result["submission_id"] == "t999"
        assert result["sandbox"] == "anyrun"

    # ---- ANYRUN get_report ------------------------------------------ #
    @pytest.mark.asyncio
    async def test_anyrun_get_report(self):
        adapter = ANYRUNAdapter(api_key="ar-key")
        report_data = {
            "data": {
                "analysis": {
                    "scores": {"verdict": {"text": "malicious"}, "specs": {"overall": 85}},
                    "tags": ["ransomware"],
                },
                "processes": [{"pid": 1}, {"pid": 2}],
                "network": {
                    "dns": [{"request": "evil.com"}],
                    "connections": [{"ip": "5.6.7.8", "port": 443}],
                    "http": [{"url": "http://evil.com/c2"}],
                },
                "iocs": {
                    "ips": ["5.6.7.8"],
                    "domains": ["evil.com"],
                    "urls": ["http://evil.com/c2"],
                    "hashes": ["deadbeef"],
                },
            }
        }
        resp_ctx = _mock_aiohttp_response(200, report_data)
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            result = await adapter.get_report("t999")

        assert result["verdict"] == "malicious"
        assert result["process_count"] == 2
        assert "evil.com" in result["network_summary"]["dns"]

    # ---- wait_for_result polls until complete ------------------------ #
    @pytest.mark.asyncio
    async def test_wait_for_result_polls_until_complete(self):
        adapter = SandboxAdapter()
        call_count = 0

        async def mock_get_status(sid):
            nonlocal call_count
            call_count += 1
            return "completed" if call_count >= 3 else "running"

        adapter.get_status = mock_get_status
        adapter.get_report = AsyncMock(return_value={"task_id": "t1", "score": 10})

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await adapter.wait_for_result("t1", timeout=300, poll_interval=10)

        assert result["score"] == 10
        assert call_count == 3

    # ---- wait_for_result timeout ------------------------------------- #
    @pytest.mark.asyncio
    async def test_wait_for_result_timeout(self):
        adapter = SandboxAdapter()
        adapter.get_status = AsyncMock(return_value="running")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await adapter.wait_for_result("t1", timeout=30, poll_interval=10)

        assert "error" in result
        assert "Timed out" in result["error"]

    # ---- wait_for_result on failure ---------------------------------- #
    @pytest.mark.asyncio
    async def test_wait_for_result_failure(self):
        adapter = SandboxAdapter()
        adapter.get_status = AsyncMock(return_value="failed")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await adapter.wait_for_result("t1", timeout=300, poll_interval=10)

        assert "error" in result
        assert result["status"] == "failed"

    # ---- adapter error handling -------------------------------------- #
    @pytest.mark.asyncio
    async def test_adapter_error_handling(self):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000")

        # Simulate aiohttp raising an exception
        def raise_error(*args, **kwargs):
            raise ConnectionError("Connection refused")

        with patch("aiohttp.ClientSession", side_effect=raise_error):
            result = await adapter.submit_file("/nonexistent.exe")
        # Should return error dict, not raise
        assert "error" in result

    # ---- CAPEv2 get_status unknown on HTTP error --------------------- #
    @pytest.mark.asyncio
    async def test_capev2_get_status_unknown_on_error(self):
        adapter = CAPEv2Adapter(api_url="http://cape.local:8000")
        resp_ctx = _mock_aiohttp_response(500)
        sess_ctx = _mock_session(resp_ctx)

        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            status = await adapter.get_status("42")
        assert status == "unknown"


class TestLLMRuleGenerator:
    @pytest.mark.asyncio
    async def test_rule_generator_prefers_provider_api(self):
        llm = SimpleNamespace(
            _call_provider_api=AsyncMock(return_value={"kql": "// provider", "sigma": "title: provider"}),
            _call_ollama_api=AsyncMock(return_value={"kql": "// ollama", "sigma": "title: ollama"}),
        )
        generator = LLMRuleGenerator(llm)

        result = await generator.generate_rules_for_ioc(
            "1.2.3.4",
            "ipv4",
            {"sources": {}, "sources_flagged": 0, "verdict": "CLEAN", "threat_score": 0},
        )

        assert result["kql"] == "// provider"
        assert result["sigma"] == "title: provider"
        llm._call_provider_api.assert_awaited_once()
        llm._call_ollama_api.assert_not_called()
