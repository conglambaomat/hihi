"""Lightweight supervised runtime queue for AgentLoop investigations."""

from __future__ import annotations

import asyncio
import queue
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class RuntimeTaskState:
    task_id: str
    session_id: str
    status: str = "queued"
    attempts: int = 0
    max_retries: int = 0
    timeout_seconds: float = 0.0
    enqueued_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    cancelled: bool = False
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AgentRuntimeSupervisor:
    """Bounded queue and worker supervision for AgentLoop background sessions."""

    def __init__(self, *, max_queue_size: int = 100, worker_count: int = 1, task_timeout_seconds: float = 0.0, max_retries: int = 0) -> None:
        self.max_queue_size = int(max_queue_size or 100)
        self.worker_count = max(1, int(worker_count or 1))
        self.task_timeout_seconds = float(task_timeout_seconds or 0.0)
        self.max_retries = max(0, int(max_retries or 0))
        self._queue: queue.Queue[str] = queue.Queue(maxsize=self.max_queue_size)
        self._tasks: Dict[str, RuntimeTaskState] = {}
        self._callbacks: Dict[str, Callable[[], Any]] = {}
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._started = False
        self._workers: List[threading.Thread] = []

    def enqueue(self, *, session_id: str, runner: Callable[[], Any]) -> Dict[str, Any]:
        with self._lock:
            if self._queue.full():
                raise RuntimeError("Agent runtime queue is full")
            task_id = "agent-task-" + uuid.uuid4().hex[:12]
            state = RuntimeTaskState(
                task_id=task_id,
                session_id=session_id,
                max_retries=self.max_retries,
                timeout_seconds=self.task_timeout_seconds,
            )
            self._tasks[task_id] = state
            self._callbacks[task_id] = runner
            self._record("queued", state)
            self._queue.put(task_id)
            self._ensure_started()
            return state.to_dict()

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            state = self._tasks.get(task_id)
            if not state or state.status in {"completed", "failed", "cancelled"}:
                return False
            state.cancelled = True
            if state.status == "queued":
                state.status = "cancelled"
                state.completed_at = time.time()
            self._record("cancelled", state)
            return True

    def state(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            state = self._tasks.get(task_id)
            return state.to_dict() if state else {}

    def status(self) -> Dict[str, Any]:
        with self._lock:
            counts: Dict[str, int] = {}
            for state in self._tasks.values():
                counts[state.status] = counts.get(state.status, 0) + 1
            return {
                "schema_version": "agent-runtime-supervisor/v1",
                "queue_enabled": True,
                "max_queue_size": self.max_queue_size,
                "worker_count": self.worker_count,
                "queue_depth": self._queue.qsize(),
                "counts": counts,
                "events": list(self._events[-50:]),
            }

    def _ensure_started(self) -> None:
        if self._started:
            return
        self._started = True
        for index in range(self.worker_count):
            worker = threading.Thread(target=self._worker, daemon=True, name=f"agent-runtime-supervisor-{index + 1}")
            worker.start()
            self._workers.append(worker)

    def _worker(self) -> None:
        while True:
            task_id = self._queue.get()
            try:
                self._run_task(task_id)
            finally:
                self._queue.task_done()

    def _run_task(self, task_id: str) -> None:
        with self._lock:
            state = self._tasks.get(task_id)
            runner = self._callbacks.get(task_id)
            if not state or not runner or state.cancelled:
                return
            state.status = "running"
            state.started_at = time.time()
            state.attempts += 1
            self._record("running", state)
        try:
            runner()
            with self._lock:
                state.status = "completed"
                state.completed_at = time.time()
                self._record("completed", state)
        except Exception as exc:
            with self._lock:
                state.last_error = str(exc)
                if state.attempts <= state.max_retries and not state.cancelled:
                    state.status = "queued"
                    self._record("retry_scheduled", state)
                    self._queue.put(task_id)
                else:
                    state.status = "failed"
                    state.completed_at = time.time()
                    self._record("failed", state)

    def _record(self, event_type: str, state: RuntimeTaskState) -> None:
        self._events.append({
            "event_type": event_type,
            "task_id": state.task_id,
            "session_id": state.session_id,
            "status": state.status,
            "attempts": state.attempts,
            "created_at": time.time(),
        })
        self._events = self._events[-100:]
