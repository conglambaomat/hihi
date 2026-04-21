"""Headless SOC daemon with durable queue, retry, and worker supervision."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .queue_store import DaemonQueueStore


class HeadlessSOCDaemon:
    """A lightweight optional scheduler facade for background workflows."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        workflow_registry=None,
        workflow_service=None,
        queue_store: Optional[DaemonQueueStore] = None,
    ):
        self.config = config or {}
        self.workflow_registry = workflow_registry
        self.workflow_service = workflow_service
        self.queue_store = queue_store or DaemonQueueStore()
        self._worker_state: Dict[str, Dict[str, Any]] = {}
        self._last_cycle_summary: Optional[Dict[str, Any]] = None
        self._last_cycle_results: List[Dict[str, Any]] = []

    def daemon_config(self) -> Dict[str, Any]:
        return dict((self.config or {}).get("daemon", {}) or {})

    def is_enabled(self) -> bool:
        return bool(self.daemon_config().get("enabled", False))

    def list_schedules(self) -> List[Dict[str, Any]]:
        schedules = self.daemon_config().get("schedules", [])
        return [
            dict(item)
            for item in schedules
            if isinstance(item, dict) and item.get("enabled", True)
        ]

    def build_status(self, app: Optional[Any] = None) -> Dict[str, Any]:
        schedules = self.list_schedules()
        validation = []
        if app is not None and self.workflow_service is not None:
            for schedule in schedules:
                workflow_id = schedule.get("workflow_id")
                if not workflow_id:
                    validation.append({"workflow_id": None, "status": "invalid"})
                    continue
                try:
                    validation.append(self.workflow_service.validate_dependencies(app, workflow_id))
                except Exception:
                    validation.append({"workflow_id": workflow_id, "status": "invalid"})
        ready_count = sum(1 for item in validation if item.get("status") == "ready")
        daemon_cfg = self.daemon_config()
        worker_states = self.worker_states()
        active_workers = [item for item in worker_states if item.get("status") == "running"]
        return {
            "enabled": self.is_enabled(),
            "runtime_mode": "thread_per_session",
            "queue_enabled": True,
            "resumable_jobs": True,
            "resumable_job_model": {
                "enabled": True,
                "resume_token": "queue_state_resume_token",
                "resume_from_statuses": ["failed", "cancelled"],
                "resume_target_status": "queued",
                "resume_scope": "queue_state_only",
            },
            "approval_aware": True,
            "bounded_concurrency": {
                "enabled": True,
                "max_workers": int(daemon_cfg.get("max_workers", 1) or 1),
                "cycle_limit": int(daemon_cfg.get("cycle_limit", 5) or 5),
                "arbitration": "queue_leasing",
                "policy": "prefer_fewer_stable_jobs",
            },
            "lease_policy": {
                "lease_timeout_seconds": int(daemon_cfg.get("lease_timeout_seconds", 300) or 300),
                "retry_backoff_seconds": int(daemon_cfg.get("retry_backoff_seconds", 60) or 60),
                "lease_expiry_transition": "retry_scheduled",
                "retryable_statuses": ["blocked"],
                "terminal_statuses": ["completed", "failed", "cancelled"],
                "cancellation_clears_lease": True,
            },
            "worker_supervision": {
                "enabled": True,
                "compatibility_mode": "thread_per_session",
                "worker_count": len(worker_states),
                "active_workers": len(active_workers),
                "workers": worker_states,
                "last_cycle": dict(self._last_cycle_summary or {}),
            },
            "migration_path": {
                "current": "optional_headless_daemon",
                "compatibility_path": "thread_per_session",
                "target": "queue_backed_worker_runtime",
            },
            "schedule_count": len(schedules),
            "ready_schedules": ready_count,
            "schedules": schedules,
            "validation": validation,
            "queue": self.queue_store.queue_stats(),
        }

    async def dispatch_schedule(self, app: Any, schedule: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one configured schedule through the workflow plane."""
        workflow_id = str(schedule.get("workflow_id") or "").strip()
        if not workflow_id:
            return {"status": "invalid", "reason": "workflow_id is required", "schedule": schedule}

        if self.workflow_registry is None or self.workflow_service is None:
            return {
                "status": "invalid",
                "workflow_id": workflow_id,
                "reason": "Workflow services are not initialized",
            }

        workflow = self.workflow_registry.get_workflow(workflow_id)
        if workflow is None:
            return {"status": "invalid", "workflow_id": workflow_id, "reason": "Workflow not found"}

        dependency_status = self.workflow_service.validate_dependencies(app, workflow_id)

        params = dict(schedule.get("params") or {})
        goal = str(schedule.get("goal") or "").strip()
        case_id = schedule.get("case_id")
        metadata = {
            "workflow_id": workflow_id,
            "agent_profile_id": workflow.get("default_agent_profile"),
            "execution_mode": "workflow",
            "schedule_name": schedule.get("name"),
            "schedule_id": schedule.get("id") or schedule.get("name") or workflow_id,
        }
        runtime_state = self.workflow_service.evaluate_runtime_readiness(
            app,
            workflow_id,
            goal=goal,
            params=params,
            metadata=metadata,
            include_dependency_status=False,
        )
        execution_surface = dict(runtime_state.get("execution_surface") or {})
        interactive_runtime_required = bool(execution_surface.get("interactive_runtime_required"))
        if dependency_status.get("status") == "blocked" or runtime_state.get("status") == "blocked":
            return {
                "status": "blocked",
                "workflow_id": workflow_id,
                "backend": workflow.get("execution_backend"),
                "dependency_status": dependency_status,
                "runtime_enforcement": runtime_state,
            }
        if interactive_runtime_required:
            return {
                "status": "blocked",
                "workflow_id": workflow_id,
                "backend": workflow.get("execution_backend"),
                "dependency_status": dependency_status,
                "runtime_enforcement": runtime_state,
                "reason": "Workflow requires interactive analyst runtime and cannot run headless.",
            }

        backend = str(workflow.get("execution_backend") or "agent").lower()
        playbook_id = workflow.get("playbook_id")
        session_id = None

        if backend == "playbook" and playbook_id:
            engine = getattr(app.state, "playbook_engine", None)
            store = getattr(app.state, "agent_store", None)
            if engine is None:
                return {
                    "status": "invalid",
                    "workflow_id": workflow_id,
                    "backend": "playbook",
                    "reason": "Playbook engine not initialized",
                }
            session_id = await engine.execute(playbook_id, params, case_id)
            if store is not None:
                store.update_session_metadata(session_id, metadata)
        else:
            agent_loop = getattr(app.state, "agent_loop", None)
            if agent_loop is None:
                return {
                    "status": "invalid",
                    "workflow_id": workflow_id,
                    "backend": "agent",
                    "reason": "Agent loop not initialized",
                }
            built_goal = self.workflow_registry.build_goal(workflow_id, goal=goal, params=params)
            session_id = await agent_loop.investigate(
                goal=built_goal,
                case_id=case_id,
                playbook_id=playbook_id,
                max_steps=schedule.get("max_steps"),
                metadata=metadata,
            )

        if case_id and getattr(app.state, "case_store", None):
            try:
                app.state.case_store.link_workflow(case_id, session_id, workflow_id)
            except Exception:
                pass

        return {
            "status": "running",
            "workflow_id": workflow_id,
            "session_id": session_id,
            "backend": backend,
            "case_id": case_id,
            "dependency_status": dependency_status,
            "runtime_enforcement": runtime_state,
            "execution_surface": execution_surface,
        }

    def worker_states(self) -> List[Dict[str, Any]]:
        return [
            dict({"worker_id": worker_id}, **state)
            for worker_id, state in sorted(self._worker_state.items())
        ]

    def mark_worker_running(self, worker_id: str, *, cycle_limit: int) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        state = self._worker_state.get(worker_id) or {}
        state.update(
            {
                "status": "running",
                "started_at": state.get("started_at") or now,
                "last_heartbeat_at": now,
                "last_cycle_started_at": now,
                "last_cycle_finished_at": state.get("last_cycle_finished_at"),
                "last_result_count": state.get("last_result_count", 0),
                "cycle_limit": int(cycle_limit),
                "last_error": "",
            }
        )
        self._worker_state[worker_id] = state
        return dict({"worker_id": worker_id}, **state)

    def mark_worker_idle(
        self,
        worker_id: str,
        *,
        result_count: int,
        cycle_limit: int,
        last_error: str = "",
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        state = self._worker_state.get(worker_id) or {}
        state.update(
            {
                "status": "idle" if not last_error else "error",
                "started_at": state.get("started_at") or now,
                "last_heartbeat_at": now,
                "last_cycle_finished_at": now,
                "last_result_count": int(result_count),
                "cycle_limit": int(cycle_limit),
                "last_error": (last_error or "")[:1000],
            }
        )
        self._worker_state[worker_id] = state
        return dict({"worker_id": worker_id}, **state)

    async def run_cycle(self, app: Any, *, worker_id: str = "headless-soc", limit: int = 5) -> List[Dict[str, Any]]:
        """Run one queue-backed daemon cycle against enabled schedules."""
        if not self.is_enabled():
            return []

        daemon_cfg = self.daemon_config()
        lease_timeout_seconds = int(daemon_cfg.get("lease_timeout_seconds", 300) or 300)
        cycle_limit = int(daemon_cfg.get("cycle_limit", limit) or limit)
        effective_limit = min(max(1, limit), max(1, cycle_limit))

        self.mark_worker_running(worker_id, cycle_limit=effective_limit)
        cycle_started_at = datetime.now(timezone.utc).isoformat()

        try:
            released_leases = self.queue_store.release_stale_leases(
                lease_timeout_seconds=lease_timeout_seconds
            )
            seeded_jobs = self.queue_store.seed_schedules(self.list_schedules())
            leased_jobs = self.queue_store.lease_due_jobs(
                worker_id,
                limit=effective_limit,
                lease_timeout_seconds=lease_timeout_seconds,
            )

            results: List[Dict[str, Any]] = []
            retry_backoff = int(daemon_cfg.get("retry_backoff_seconds", 60) or 60)
            for job in leased_jobs:
                schedule = dict(job.get("schedule") or {})
                dispatch = await self.dispatch_schedule(app, schedule)
                dispatch["queue_job_id"] = job["id"]
                dispatch["resume_token"] = job.get("resume_token")
                dispatch["worker_id"] = worker_id
                dispatch["runtime_mode"] = "thread_per_session"
                dispatch["lease_expires_at"] = job.get("lease_expires_at")
                results.append(dispatch)

                if dispatch.get("status") == "running":
                    self.queue_store.complete_job(job["id"], session_id=dispatch.get("session_id"))
                    continue

                retryable = dispatch.get("status") in {"blocked"}
                error = dispatch.get("reason") or dispatch.get("dependency_status", {}).get("status") or dispatch.get("status", "unknown_error")
                retry_state = self.queue_store.fail_job(
                    job["id"],
                    str(error),
                    retryable=retryable,
                    base_backoff_seconds=retry_backoff,
                )
                dispatch["queue_retry"] = retry_state

            self._last_cycle_results = [dict(item) for item in results]
            self._last_cycle_summary = {
                "worker_id": worker_id,
                "status": "completed",
                "runtime_mode": "thread_per_session",
                "started_at": cycle_started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "released_stale_leases": released_leases,
                "seeded_jobs": seeded_jobs,
                "leased_jobs": len(leased_jobs),
                "result_count": len(results),
                "cycle_limit": effective_limit,
            }
            self.mark_worker_idle(worker_id, result_count=len(results), cycle_limit=effective_limit)
            return results
        except Exception as exc:
            self._last_cycle_summary = {
                "worker_id": worker_id,
                "status": "error",
                "runtime_mode": "thread_per_session",
                "started_at": cycle_started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "cycle_limit": effective_limit,
                "error": str(exc)[:1000],
            }
            self.mark_worker_idle(
                worker_id,
                result_count=0,
                cycle_limit=effective_limit,
                last_error=str(exc),
            )
            raise

    async def run_once(self, runner: Callable[[Dict[str, Any]], Any]) -> List[Any]:
        """Execute one polling cycle by delegating schedules to *runner*."""
        results = []
        for schedule in self.list_schedules():
            if not schedule.get("enabled", True):
                continue
            results.append(await runner(schedule))
        return results
