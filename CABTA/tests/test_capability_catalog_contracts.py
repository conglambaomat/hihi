from types import SimpleNamespace

from src.agent.capability_catalog import CapabilityCatalog
from src.agent.profiles import AgentProfileRegistry
from src.agent.tool_registry import ToolRegistry
from src.daemon.service import HeadlessSOCDaemon
from src.daemon.queue_store import DaemonQueueStore
from src.workflows.registry import WorkflowRegistry
from src.workflows.service import WorkflowService
from src.agent.agent_store import AgentStore


async def _noop(**kwargs):
    return {}


def test_build_summary_exposes_readiness_flags(tmp_path):
    registry = ToolRegistry()
    registry.register_local_tool("investigate_ioc", "IOC", {}, "analysis", _noop)

    app = SimpleNamespace(
        state=SimpleNamespace(
            tool_registry=registry,
            agent_profiles=AgentProfileRegistry.default(),
            workflow_registry=None,
            workflow_service=None,
            playbook_engine=None,
            mcp_client=SimpleNamespace(get_connection_status=lambda: {}),
            governance_store=None,
            headless_soc_daemon=None,
            ioc_investigator=object(),
            malware_analyzer=object(),
            email_analyzer=object(),
            case_store=object(),
            analysis_manager=object(),
        )
    )

    summary = CapabilityCatalog().build_summary(app)

    assert summary["verdict_authority_owner"] == "cabta_scoring"
    assert summary["tool_count"] >= 1
    assert summary["analysis_core_ready"] is True
    assert summary["mcp_ready"] is False
    assert summary["daemon_runtime_status"] == "not_configured"


def test_build_catalog_exposes_control_plane_and_truth_metadata(tmp_path):
    registry = ToolRegistry()
    registry.register_local_tool("investigate_ioc", "IOC", {}, "analysis", _noop)
    registry.register_mcp_tools(
        "splunk-mcp",
        [
            {
                "name": "search_logs",
                "description": "Search Splunk logs",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                "category": "analysis",
            }
        ],
    )

    workflow_registry = WorkflowRegistry()
    agent_store = AgentStore(db_path=str(tmp_path / "agent.db"))
    workflow_service = WorkflowService(workflow_registry=workflow_registry, agent_store=agent_store)
    daemon = HeadlessSOCDaemon(
        config={"daemon": {"enabled": True, "max_workers": 2, "cycle_limit": 4}},
        workflow_registry=workflow_registry,
        workflow_service=workflow_service,
        queue_store=DaemonQueueStore(db_path=str(tmp_path / "daemon.db")),
    )

    app = SimpleNamespace(
        state=SimpleNamespace(
            tool_registry=registry,
            agent_profiles=AgentProfileRegistry.default(),
            workflow_registry=workflow_registry,
            workflow_service=workflow_service,
            playbook_engine=None,
            mcp_client=SimpleNamespace(
                get_connection_status=lambda: {
                    "splunk-mcp": {"connected": True, "tool_count": 1},
                    "other-mcp": {"connected": False, "tool_count": 0},
                }
            ),
            governance_store=object(),
            headless_soc_daemon=daemon,
            ioc_investigator=object(),
            malware_analyzer=object(),
            email_analyzer=object(),
            case_store=object(),
            analysis_manager=object(),
            agent_loop=object(),
        )
    )

    catalog = CapabilityCatalog().build_catalog(app)

    assert catalog["tools"]["truth"]["status"] == "ready"
    assert catalog["tools"]["truth"]["local_available"] == 1
    assert catalog["tools"]["truth"]["mcp_available"] == 1

    assert catalog["mcp"]["configured"] == 2
    assert catalog["mcp"]["connected"] == 1
    assert catalog["mcp"]["truth"]["inventory_present"] is True
    assert catalog["mcp"]["truth"]["configured_servers"] == 2
    assert catalog["mcp"]["truth"]["connected_servers"] == 1
    assert catalog["mcp"]["truth"]["disconnected_servers"] == 1
    assert catalog["mcp"]["truth"]["runtime_connected"] is True
    assert catalog["mcp"]["readiness"]["status"] == "ready"
    assert "other-mcp" in catalog["mcp"]["disconnected_servers"]

    assert catalog["workflows"]["readiness"]["status"] == "ready"
    assert catalog["workflows"]["dependency_mode"] == "validated"
    assert catalog["workflows"]["truth"]["inventory_present"] is True
    assert catalog["workflows"]["truth"]["runtime_service_present"] is True
    assert catalog["workflows"]["truth"]["validated_runtime"] is True

    assert catalog["orchestration_plane"]["daemon_runtime"]["status"] == "ready"
    assert catalog["orchestration_plane"]["daemon_runtime"]["queue_enabled"] is True
    assert catalog["orchestration_plane"]["daemon_runtime"]["resumable_jobs"] is True
    assert catalog["orchestration_plane"]["daemon_runtime"]["resumable_job_model"]["resume_scope"] == "queue_state_only"
    assert catalog["orchestration_plane"]["daemon_runtime"]["bounded_concurrency"]["arbitration"] == "queue_leasing"
    assert catalog["orchestration_plane"]["daemon_runtime"]["lease_policy"]["lease_expiry_transition"] == "retry_scheduled"
    assert catalog["orchestration_plane"]["daemon_runtime"]["migration_path"]["target"] == "queue_backed_worker_runtime"
    assert catalog["orchestration_plane"]["governance"]["status"] == "ready"
    assert catalog["orchestration_plane"]["governance"]["store_present"] is True
    assert catalog["orchestration_plane"]["governance"]["approval_logging"] is True
    assert catalog["orchestration_plane"]["governance"]["decision_feedback_logging"] is True
    assert catalog["orchestration_plane"]["governance"]["summary"]["approvals"]["total"] == 0
    assert catalog["orchestration_plane"]["governance"]["summary"]["ai_decisions"]["total"] == 0
    assert catalog["orchestration_plane"]["control_plane"]["tool_truth_explicit"] is True
    assert catalog["orchestration_plane"]["control_plane"]["workflow_truth_explicit"] is True
    assert catalog["orchestration_plane"]["control_plane"]["mcp_truth_explicit"] is True
    assert catalog["orchestration_plane"]["control_plane"]["daemon_runtime_truth_explicit"] is True
    assert catalog["orchestration_plane"]["control_plane"]["governance_truth_explicit"] is True

    assert catalog["analysis_core"]["readiness"]["status"] == "ready"
    assert catalog["verdict_authority"]["owner"] == "cabta_scoring"
