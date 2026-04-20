import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.daemon.queue_store import DaemonQueueStore


def build_store(tmp_path):
    return DaemonQueueStore(db_path=str(tmp_path / "daemon.db"))


def test_seed_and_lease_due_jobs_sets_lease_metadata(tmp_path):
    store = build_store(tmp_path)
    queued = store.seed_schedules(
        [
            {
                "id": "sched-1",
                "workflow_id": "wf-1",
                "enabled": True,
                "max_attempts": 4,
            }
        ]
    )

    assert queued == 1

    leased = store.lease_due_jobs("worker-a", limit=1, lease_timeout_seconds=120)
    assert len(leased) == 1

    job = leased[0]
    assert job["status"] == "leased"
    assert job["lease_owner"] == "worker-a"
    assert job["lease_expires_at"] is not None
    assert job["last_transition"] == "leased"
    assert job["attempts"] == 1
    assert job["resume_token"]


def test_release_stale_leases_moves_job_to_retry_scheduled(tmp_path):
    store = build_store(tmp_path)
    store.seed_schedules([{"id": "sched-2", "workflow_id": "wf-2", "enabled": True}])
    leased = store.lease_due_jobs("worker-a", limit=1, lease_timeout_seconds=30)
    job_id = leased[0]["id"]

    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    conn = store._connect()
    conn.execute(
        "UPDATE daemon_queue SET leased_at = ?, status = 'leased' WHERE id = ?",
        (stale_time, job_id),
    )
    conn.commit()
    conn.close()

    released = store.release_stale_leases(lease_timeout_seconds=300)
    assert released == 1

    job = store.get_job(job_id)
    assert job is not None
    assert job["status"] == "retry_scheduled"
    assert job["lease_owner"] is None
    assert job["lease_expires_at"] is None
    assert job["last_transition"] == "lease_released"


def test_cancel_and_resume_job_round_trip(tmp_path):
    store = build_store(tmp_path)
    store.seed_schedules([{"id": "sched-3", "workflow_id": "wf-3", "enabled": True}])
    job = store.lease_due_jobs("worker-b", limit=1)[0]

    cancelled = store.cancel_job(job["id"], reason="analyst_cancelled")
    assert cancelled is True

    cancelled_job = store.get_job(job["id"])
    assert cancelled_job["status"] == "cancelled"
    assert cancelled_job["last_error"] == "analyst_cancelled"
    assert cancelled_job["last_transition"] == "cancelled"

    resumed = store.resume_job(job["id"])
    assert resumed is True

    resumed_job = store.get_job(job["id"])
    assert resumed_job["status"] == "queued"
    assert resumed_job["last_transition"] == "resumed"
    assert resumed_job["lease_owner"] is None


def test_fail_job_sets_retry_or_terminal_failed_state(tmp_path):
    store = build_store(tmp_path)
    store.seed_schedules([{"id": "sched-4", "workflow_id": "wf-4", "enabled": True, "max_attempts": 3}])
    leased = store.lease_due_jobs("worker-c", limit=1)[0]

    retry_state = store.fail_job(leased["id"], "backend_blocked", retryable=True, base_backoff_seconds=10)
    assert retry_state["status"] == "retry_scheduled"
    assert retry_state["retry_in_seconds"] == 10

    retry_job = store.get_job(leased["id"])
    assert retry_job["status"] == "retry_scheduled"
    assert retry_job["last_transition"] == "retry_scheduled"

    store.lease_due_jobs("worker-c", limit=1)
    store.lease_due_jobs("worker-c", limit=1)

    terminal_state = store.fail_job(leased["id"], "hard_failure", retryable=False, base_backoff_seconds=10)
    assert terminal_state["status"] == "failed"

    failed_job = store.get_job(leased["id"])
    assert failed_job["status"] == "failed"
    assert failed_job["last_transition"] == "failed"


def test_queue_stats_includes_cancelled(tmp_path):
    store = build_store(tmp_path)
    store.seed_schedules([{"id": "sched-5", "workflow_id": "wf-5", "enabled": True}])
    job = store.lease_due_jobs("worker-d", limit=1)[0]
    store.cancel_job(job["id"])

    stats = store.queue_stats()
    assert stats["cancelled"] == 1