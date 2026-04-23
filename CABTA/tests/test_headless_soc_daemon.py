import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.daemon.queue_store import DaemonQueueStore
from src.daemon.service import HeadlessSOCDaemon


class StubWorkflowRegistry:
    def get_workflow(self, workflow_id):
        return {
            "id": workflow_id,
            "execution_backend": "agent",
            "default_agent_profile": "investigator",
            "playbook_id": None,
        }

    def build_goal(self, workflow_id, goal="", params=None):
        return f"{workflow_id}:{goal or 'scheduled-run'}"


class StubWorkflowService:
    def validate_dependencies(self, app, workflow_id):
        return {"workflow_id": workflow_id, "status": "ready"}

    def evaluate_runtime_readiness(self, app, workflow_id, **kwargs):
        dependency_status = dict(kwargs.get("dependency_status_override") or {"status": "unknown"})
        return {
            "workflow_id": workflow_id,
            "status": "ready",
            "runtime_truth_contract": {
                "dependency_status": dependency_status.get("status", "unknown"),
            },
            "execution_surface": {
                "headless_ready": True,
                "supports_headless_execution": True,
                "interactive_runtime_required": False,
                "headless_blockers": [],
                "runtime_mode": "headless_or_interactive",
            },
        }


@pytest.mark.anyio
async def test_build_status_exposes_runtime_migration_and_concurrency(tmp_path):
    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "max_workers": 3,
                "cycle_limit": 7,
                "lease_timeout_seconds": 123,
                "retry_backoff_seconds": 45,
                "schedules": [{"id": "sched-1", "workflow_id": "wf-1"}],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=StubWorkflowService(),
        queue_store=DaemonQueueStore(db_path=str(tmp_path / "daemon.db")),
    )

    status = daemon.build_status(app=SimpleNamespace())

    assert status["enabled"] is True
    assert status["runtime_mode"] == "thread_per_session"
    assert status["resumable_jobs"] is True
    assert status["resumable_job_model"]["enabled"] is True
    assert status["resumable_job_model"]["resume_token"] == "queue_state_resume_token"
    assert status["resumable_job_model"]["resume_from_statuses"] == ["failed", "cancelled"]
    assert status["resumable_job_model"]["resume_target_status"] == "queued"
    assert status["resumable_job_model"]["resume_scope"] == "queue_state_only"
    assert status["bounded_concurrency"]["max_workers"] == 3
    assert status["bounded_concurrency"]["cycle_limit"] == 7
    assert status["bounded_concurrency"]["arbitration"] == "queue_leasing"
    assert status["bounded_concurrency"]["policy"] == "prefer_fewer_stable_jobs"
    assert status["lease_policy"]["lease_timeout_seconds"] == 123
    assert status["lease_policy"]["retry_backoff_seconds"] == 45
    assert status["lease_policy"]["lease_expiry_transition"] == "retry_scheduled"
    assert status["lease_policy"]["retryable_statuses"] == ["blocked"]
    assert status["lease_policy"]["terminal_statuses"] == ["completed", "failed", "cancelled"]
    assert status["lease_policy"]["cancellation_clears_lease"] is True
    assert status["migration_path"]["target"] == "queue_backed_worker_runtime"
    assert status["worker_supervision"]["enabled"] is True
    assert status["worker_supervision"]["compatibility_mode"] == "thread_per_session"
    assert status["worker_supervision"]["worker_count"] == 0
    assert status["worker_supervision"]["last_cycle"] == {}


@pytest.mark.anyio
async def test_run_cycle_adds_runtime_metadata_and_completes_running_jobs(tmp_path):
    queue_store = DaemonQueueStore(db_path=str(tmp_path / "daemon.db"))
    agent_loop = MagicMock()
    agent_loop.investigate = AsyncMock(return_value="sess-123")

    app = SimpleNamespace(
        state=SimpleNamespace(
            agent_loop=agent_loop,
            case_store=None,
        )
    )

    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "cycle_limit": 2,
                "lease_timeout_seconds": 60,
                "retry_backoff_seconds": 30,
                "schedules": [
                    {"id": "sched-1", "workflow_id": "wf-1", "goal": "hunt"},
                ],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=StubWorkflowService(),
        queue_store=queue_store,
    )

    results = await daemon.run_cycle(app, worker_id="worker-z", limit=5)

    assert len(results) == 1
    result = results[0]
    assert result["status"] == "running"
    assert result["worker_id"] == "worker-z"
    assert result["runtime_mode"] == "thread_per_session"
    assert result["runtime_truth"] == "workflow_runtime_enforcement"
    assert result["runtime_truth_contract"] == {"dependency_status": "ready"}
    assert result["headless_execution_eligible"] is True
    assert result["case_truth_ready"] is True
    assert result["resume_token"]
    assert result["lease_expires_at"] is not None
    assert result["execution_surface"]["supports_headless_execution"] is True
    assert result["runtime_enforcement"]["runtime_truth_contract"]["dependency_status"] == "ready"

    job = queue_store.get_job(result["queue_job_id"])
    assert job is not None
    assert job["status"] == "completed"
    assert job["last_transition"] == "completed"


@pytest.mark.anyio
async def test_run_cycle_respects_cycle_limit_and_marks_blocked_jobs_retryable(tmp_path):
    queue_store = DaemonQueueStore(db_path=str(tmp_path / "daemon.db"))

    class BlockedWorkflowService:
        def validate_dependencies(self, app, workflow_id):
            return {"workflow_id": workflow_id, "status": "blocked"}

        def evaluate_runtime_readiness(self, app, workflow_id, **kwargs):
            return {
                "workflow_id": workflow_id,
                "status": "ready",
                "execution_surface": {
                    "headless_ready": True,
                    "supports_headless_execution": True,
                    "interactive_runtime_required": False,
                    "headless_blockers": [],
                    "runtime_mode": "headless_or_interactive",
                },
            }

    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "cycle_limit": 1,
                "lease_timeout_seconds": 50,
                "retry_backoff_seconds": 15,
                "schedules": [
                    {"id": "sched-a", "workflow_id": "wf-a"},
                    {"id": "sched-b", "workflow_id": "wf-b"},
                ],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=BlockedWorkflowService(),
        queue_store=queue_store,
    )

    app = SimpleNamespace(state=SimpleNamespace(agent_loop=None, case_store=None))

    results = await daemon.run_cycle(app, worker_id="worker-b", limit=5)

    assert len(results) == 1
    result = results[0]
    assert result["status"] == "blocked"
    assert result["runtime_truth"] == "workflow_runtime_enforcement"
    assert result["runtime_truth_contract"] == {}
    assert result["headless_execution_eligible"] is True
    assert result["case_truth_ready"] is False
    assert result["queue_retry"]["status"] == "retry_scheduled"
    assert result["queue_retry"]["retry_in_seconds"] == 15


@pytest.mark.anyio
async def test_dispatch_schedule_blocks_interactive_only_workflows_in_headless_runtime(tmp_path):
    queue_store = DaemonQueueStore(db_path=str(tmp_path / "daemon-headless.db"))

    class InteractiveOnlyWorkflowService(StubWorkflowService):
        def evaluate_runtime_readiness(self, app, workflow_id, **kwargs):
            return {
                "workflow_id": workflow_id,
                "status": "degraded",
                "execution_surface": {
                    "headless_declared": True,
                    "headless_ready": True,
                    "supports_headless_execution": False,
                    "interactive_runtime_required": True,
                    "headless_blockers": ["approval_checkpoints_require_interactive_runtime"],
                    "runtime_mode": "interactive_only",
                    "optional_runtime_degraded": False,
                    "optional_runtime_blockers": [],
                    "dependency_status": "degraded",
                    "capability_scope": "workflow_runtime_contract",
                },
            }

    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "schedules": [{"id": "sched-analyst", "workflow_id": "wf-analyst", "goal": "hunt"}],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=InteractiveOnlyWorkflowService(),
        queue_store=queue_store,
    )

    app = SimpleNamespace(state=SimpleNamespace(agent_loop=None, case_store=None))

    result = await daemon.dispatch_schedule(app, {"id": "sched-analyst", "workflow_id": "wf-analyst", "goal": "hunt"})

    assert result["status"] == "blocked"
    assert result["runtime_truth"] == "workflow_runtime_enforcement"
    assert result["runtime_truth_contract"] == {}
    assert result["headless_execution_eligible"] is False
    assert result["case_truth_ready"] is True
    assert result["reason"] == "Workflow requires interactive analyst runtime and cannot run headless."
    assert result["runtime_enforcement"]["status"] == "degraded"
    assert result["runtime_enforcement"]["execution_surface"]["interactive_runtime_required"] is True
    assert result["runtime_enforcement"]["execution_surface"]["headless_blockers"] == [
        "approval_checkpoints_require_interactive_runtime"
    ]
    assert result["runtime_enforcement"]["execution_surface"]["capability_scope"] == "workflow_runtime_contract"
    assert result["runtime_enforcement"]["execution_surface"]["dependency_status"] == "degraded"


@pytest.mark.anyio
async def test_run_cycle_updates_worker_supervision_and_last_cycle_status(tmp_path):
    queue_store = DaemonQueueStore(db_path=str(tmp_path / "daemon.db"))
    agent_loop = MagicMock()
    agent_loop.investigate = AsyncMock(return_value="sess-999")

    app = SimpleNamespace(
        state=SimpleNamespace(
            agent_loop=agent_loop,
            case_store=None,
        )
    )

    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "cycle_limit": 2,
                "lease_timeout_seconds": 60,
                "retry_backoff_seconds": 30,
                "schedules": [
                    {"id": "sched-1", "workflow_id": "wf-1", "goal": "hunt"}
                ],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=StubWorkflowService(),
        queue_store=queue_store,
    )

    await daemon.run_cycle(app, worker_id="worker-supervisor", limit=5)

    status = daemon.build_status(app=app)
    supervision = status["worker_supervision"]

    assert supervision["worker_count"] == 1
    assert supervision["active_workers"] == 0
    assert supervision["last_cycle"]["worker_id"] == "worker-supervisor"
    assert supervision["last_cycle"]["status"] == "completed"
    assert supervision["last_cycle"]["leased_jobs"] == 1
    assert supervision["last_cycle"]["result_count"] == 1
    assert supervision["workers"][0]["worker_id"] == "worker-supervisor"
    assert supervision["workers"][0]["status"] == "idle"
    assert supervision["workers"][0]["last_result_count"] == 1
    assert supervision["workers"][0]["last_cycle_finished_at"] is not None


@pytest.mark.anyio
async def test_run_cycle_marks_worker_error_when_dispatch_raises(tmp_path):
    queue_store = DaemonQueueStore(db_path=str(tmp_path / "daemon.db"))

    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "cycle_limit": 1,
                "lease_timeout_seconds": 60,
                "retry_backoff_seconds": 30,
                "schedules": [{"id": "sched-err", "workflow_id": "wf-err"}],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=StubWorkflowService(),
        queue_store=queue_store,
    )

    async def _boom(app, schedule):
        raise RuntimeError("dispatch exploded")

    daemon.dispatch_schedule = _boom

    app = SimpleNamespace(state=SimpleNamespace(agent_loop=None, case_store=None))

    with pytest.raises(RuntimeError, match="dispatch exploded"):
        await daemon.run_cycle(app, worker_id="worker-error", limit=2)

    status = daemon.build_status(app=app)
    supervision = status["worker_supervision"]

    assert supervision["worker_count"] == 1
    assert supervision["active_workers"] == 0
    assert supervision["last_cycle"]["status"] == "error"
    assert supervision["last_cycle"]["error"] == "dispatch exploded"
    assert supervision["workers"][0]["worker_id"] == "worker-error"
    assert supervision["workers"][0]["status"] == "error"
    assert supervision["workers"][0]["last_error"] == "dispatch exploded"


@pytest.mark.anyio
async def test_run_cycle_ignores_disabled_schedules_for_queue_seeding_and_dispatch(tmp_path):
    queue_store = DaemonQueueStore(db_path=str(tmp_path / "daemon.db"))
    agent_loop = MagicMock()
    agent_loop.investigate = AsyncMock(return_value="sess-disabled-filter")

    app = SimpleNamespace(
        state=SimpleNamespace(
            agent_loop=agent_loop,
            case_store=None,
        )
    )

    daemon = HeadlessSOCDaemon(
        config={
            "daemon": {
                "enabled": True,
                "cycle_limit": 5,
                "lease_timeout_seconds": 60,
                "retry_backoff_seconds": 30,
                "schedules": [
                    {"id": "sched-enabled", "workflow_id": "wf-enabled", "goal": "hunt enabled"},
                    {"id": "sched-disabled", "workflow_id": "wf-disabled", "goal": "hunt disabled", "enabled": False},
                ],
            }
        },
        workflow_registry=StubWorkflowRegistry(),
        workflow_service=StubWorkflowService(),
        queue_store=queue_store,
    )

    results = await daemon.run_cycle(app, worker_id="worker-filter", limit=5)

    assert len(results) == 1
    assert results[0]["workflow_id"] == "wf-enabled"
    assert queue_store.queue_stats() == {
        "queued": 0,
        "leased": 0,
        "retry_scheduled": 0,
        "completed": 1,
        "failed": 0,
        "cancelled": 0,
    }
    enabled_job = queue_store.get_job(results[0]["queue_job_id"])
    assert enabled_job is not None
    assert enabled_job["schedule_id"] == "sched-enabled"
    agent_loop.investigate.assert_awaited_once()
