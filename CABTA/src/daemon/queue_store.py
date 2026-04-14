"""SQLite-backed durable queue for headless SOC workflow dispatch."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_DB = Path.home() / ".blue-team-assistant" / "cache" / "daemon.db"


class DaemonQueueStore:
    """Persist scheduled workflow dispatches with retry/backoff semantics."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        self._init_db()

    def seed_schedules(self, schedules: List[Dict[str, Any]]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        queued = 0
        with self._lock:
            conn = self._connect()
            for schedule in schedules:
                if not isinstance(schedule, dict) or not schedule.get("enabled", True):
                    continue
                schedule_id = str(schedule.get("id") or schedule.get("name") or schedule.get("workflow_id") or "").strip()
                workflow_id = str(schedule.get("workflow_id") or "").strip()
                if not schedule_id or not workflow_id:
                    continue
                cur = conn.execute(
                    """SELECT 1 FROM daemon_queue
                       WHERE schedule_id = ? AND status IN ('queued', 'leased', 'retry_scheduled')""",
                    (schedule_id,),
                )
                if cur.fetchone():
                    continue
                conn.execute(
                    """INSERT INTO daemon_queue
                       (id, schedule_id, workflow_id, schedule_json, status, attempts,
                        max_attempts, next_run_at, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?)""",
                    (
                        uuid.uuid4().hex[:12],
                        schedule_id,
                        workflow_id,
                        json.dumps(schedule, default=str),
                        int(schedule.get("max_attempts") or 3),
                        now,
                        now,
                        now,
                    ),
                )
                queued += 1
            conn.commit()
            conn.close()
        return queued

    def release_stale_leases(self, *, lease_timeout_seconds: int = 300) -> int:
        stale_before = (datetime.now(timezone.utc) - timedelta(seconds=lease_timeout_seconds)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                """UPDATE daemon_queue
                   SET status = 'retry_scheduled', lease_owner = NULL, leased_at = NULL, updated_at = ?
                   WHERE status = 'leased' AND leased_at IS NOT NULL AND leased_at <= ?""",
                (now, stale_before),
            )
            conn.commit()
            count = cur.rowcount
            conn.close()
        return count

    def lease_due_jobs(self, worker_id: str, *, limit: int = 5) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        leased_ids: List[str] = []
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                """SELECT id FROM daemon_queue
                   WHERE status IN ('queued', 'retry_scheduled') AND next_run_at <= ?
                   ORDER BY next_run_at ASC, created_at ASC LIMIT ?""",
                (now, limit),
            )
            leased_ids = [row[0] for row in cur.fetchall()]
            for job_id in leased_ids:
                conn.execute(
                    """UPDATE daemon_queue
                       SET status = 'leased', leased_at = ?, lease_owner = ?, attempts = attempts + 1, updated_at = ?
                       WHERE id = ?""",
                    (now, worker_id, now, job_id),
                )
            conn.commit()
            conn.close()
        return [self.get_job(job_id) for job_id in leased_ids if self.get_job(job_id)]

    def complete_job(self, job_id: str, *, session_id: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """UPDATE daemon_queue
                   SET status = 'completed', session_id = ?, lease_owner = NULL, leased_at = NULL, updated_at = ?
                   WHERE id = ?""",
                (session_id, now, job_id),
            )
            conn.commit()
            conn.close()

    def fail_job(self, job_id: str, error: str, *, retryable: bool, base_backoff_seconds: int = 60) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        with self._lock:
            conn = self._connect()
            cur = conn.execute("SELECT attempts, max_attempts FROM daemon_queue WHERE id = ?", (job_id,))
            row = cur.fetchone()
            attempts, max_attempts = (row[0], row[1]) if row else (0, 0)
            if retryable and attempts < max_attempts:
                delay = base_backoff_seconds * max(1, 2 ** max(attempts - 1, 0))
                next_run_at = (now + timedelta(seconds=delay)).isoformat()
                status = "retry_scheduled"
            else:
                delay = 0
                next_run_at = now.isoformat()
                status = "failed"
            conn.execute(
                """UPDATE daemon_queue
                   SET status = ?, next_run_at = ?, last_error = ?, lease_owner = NULL, leased_at = NULL, updated_at = ?
                   WHERE id = ?""",
                (status, next_run_at, error[:1000], now.isoformat(), job_id),
            )
            conn.commit()
            conn.close()
        return {"status": status, "retry_in_seconds": delay, "next_run_at": next_run_at}

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute("SELECT * FROM daemon_queue WHERE id = ?", (job_id,))
        row = cur.fetchone()
        desc = cur.description
        conn.close()
        return self._row_to_dict(desc, row) if row else None

    def queue_stats(self) -> Dict[str, int]:
        conn = self._connect()
        cur = conn.execute(
            """SELECT status, COUNT(*) FROM daemon_queue GROUP BY status"""
        )
        counts = {status: count for status, count in cur.fetchall()}
        conn.close()
        return {
            "queued": counts.get("queued", 0),
            "leased": counts.get("leased", 0),
            "retry_scheduled": counts.get("retry_scheduled", 0),
            "completed": counts.get("completed", 0),
            "failed": counts.get("failed", 0),
        }

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS daemon_queue (
                id           TEXT PRIMARY KEY,
                schedule_id  TEXT NOT NULL,
                workflow_id  TEXT NOT NULL,
                schedule_json TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'queued',
                attempts     INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                next_run_at  TEXT NOT NULL,
                leased_at    TEXT,
                lease_owner  TEXT,
                session_id   TEXT,
                last_error   TEXT DEFAULT '',
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_daemon_queue_due ON daemon_queue(status, next_run_at)")
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    @staticmethod
    def _row_to_dict(description, row) -> Dict[str, Any]:
        payload = dict(zip([item[0] for item in description], row))
        if payload.get("schedule_json"):
            try:
                payload["schedule"] = json.loads(payload["schedule_json"])
            except Exception:
                payload["schedule"] = {}
        return payload
