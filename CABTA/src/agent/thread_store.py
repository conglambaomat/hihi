"""Thread-level chat memory separate from execution sessions."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_db_path() -> Path:
    explicit = os.environ.get("CABTA_THREAD_DB")
    if explicit:
        return Path(explicit)
    home_override = os.environ.get("CABTA_HOME")
    home_path = Path(home_override) if home_override else Path.home()
    return home_path / ".cabta-runtime" / "threads.db"


class ThreadStore:
    """Persist conversation threads and lifecycle-aware latest thread snapshots."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _default_db_path()
        self._lock = threading.Lock()
        self._init_db()

    def ensure_thread(
        self,
        *,
        thread_id: Optional[str] = None,
        case_id: Optional[str] = None,
        root_session_id: Optional[str] = None,
        status: str = "active",
    ) -> str:
        if thread_id:
            existing = self.get_thread(thread_id)
            if existing is not None:
                return thread_id
        return self.create_thread(case_id=case_id, root_session_id=root_session_id, status=status)

    def create_thread(
        self,
        *,
        case_id: Optional[str] = None,
        root_session_id: Optional[str] = None,
        status: str = "active",
    ) -> str:
        thread_id = uuid.uuid4().hex[:12]
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO investigation_threads
                    (id, case_id, root_session_id, last_session_id, thread_summary,
                     last_snapshot_id, last_snapshot_json, pinned_entities_json,
                     pinned_questions_json, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, '', NULL, '{}', '[]', '[]', ?, ?, ?)
                """,
                (thread_id, case_id, root_session_id, root_session_id, status, now, now),
            )
            conn.commit()
            conn.close()
        return thread_id

    def get_thread(self, thread_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute("SELECT * FROM investigation_threads WHERE id = ?", (thread_id,))
        row = cur.fetchone()
        desc = cur.description
        conn.close()
        if row is None:
            return None
        payload = self._row_to_dict(desc, row)
        snapshot_record = self._build_snapshot_record(
            snapshot_id=payload.get("last_snapshot_id"),
            snapshot_value=payload.get("last_thread_snapshot"),
            pinned_entities_value=payload.get("pinned_entities"),
            pinned_questions_value=payload.get("pinned_questions"),
        )
        payload["last_thread_snapshot_authority_scope"] = snapshot_record.get("authority_scope")
        payload["last_thread_snapshot_lifecycle"] = snapshot_record.get("snapshot_lifecycle")
        payload["messages"] = self.list_messages(thread_id)
        payload["pending_commands"] = self.list_commands(thread_id, statuses=("pending", "in_progress"))
        return payload

    def append_message(
        self,
        *,
        thread_id: str,
        role: str,
        content: str,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        message_id = uuid.uuid4().hex[:12]
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO thread_messages
                    (id, thread_id, session_id, role, content, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    thread_id,
                    session_id,
                    role,
                    content,
                    json.dumps(metadata or {}, default=str),
                    now,
                ),
            )
            conn.execute(
                "UPDATE investigation_threads SET last_session_id = COALESCE(?, last_session_id), updated_at = ? WHERE id = ?",
                (session_id, now, thread_id),
            )
            conn.commit()
            conn.close()
        return message_id

    def list_messages(self, thread_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute(
            """
            SELECT id, thread_id, session_id, role, content, metadata_json, created_at
            FROM thread_messages
            WHERE thread_id = ?
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (thread_id, limit),
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, row) for row in rows]

    def update_thread_snapshot(
        self,
        *,
        thread_id: str,
        snapshot: Dict[str, Any],
        last_session_id: Optional[str] = None,
        thread_summary: Optional[str] = None,
        pinned_entities: Optional[List[str]] = None,
        pinned_questions: Optional[List[str]] = None,
        status: Optional[str] = None,
    ) -> str:
        snapshot_id = uuid.uuid4().hex[:12]
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                UPDATE investigation_threads
                SET last_session_id = COALESCE(?, last_session_id),
                    thread_summary = COALESCE(?, thread_summary),
                    last_snapshot_id = ?,
                    last_snapshot_json = ?,
                    pinned_entities_json = COALESCE(?, pinned_entities_json),
                    pinned_questions_json = COALESCE(?, pinned_questions_json),
                    status = COALESCE(?, status),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    last_session_id,
                    thread_summary,
                    snapshot_id,
                    json.dumps(snapshot or {}, default=str),
                    json.dumps(pinned_entities or [], default=str) if pinned_entities is not None else None,
                    json.dumps(pinned_questions or [], default=str) if pinned_questions is not None else None,
                    status,
                    now,
                    thread_id,
                ),
            )
            conn.commit()
            conn.close()
        return snapshot_id

    def enqueue_command(
        self,
        *,
        thread_id: str,
        content: str,
        session_id: Optional[str] = None,
        intent: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        command_id = uuid.uuid4().hex[:12]
        now = _now_iso()
        clean_payload = dict(payload or {})
        if intent and not clean_payload.get("intent"):
            clean_payload["intent"] = intent
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO thread_commands
                    (id, thread_id, session_id, intent, content, payload_json, result_json, status, created_at, updated_at, processed_at)
                VALUES (?, ?, ?, ?, ?, ?, '{}', 'pending', ?, ?, NULL)
                """,
                (
                    command_id,
                    thread_id,
                    session_id,
                    intent,
                    content,
                    json.dumps(clean_payload, default=str),
                    now,
                    now,
                ),
            )
            conn.execute(
                "UPDATE investigation_threads SET updated_at = ? WHERE id = ?",
                (now, thread_id),
            )
            conn.commit()
            conn.close()
        return command_id

    def list_commands(
        self,
        thread_id: str,
        *,
        statuses: Optional[tuple[str, ...]] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        active_statuses = tuple(statuses or ("pending", "in_progress", "completed"))
        placeholders = ",".join("?" for _ in active_statuses)
        conn = self._connect()
        cur = conn.execute(
            f"""
            SELECT id, thread_id, session_id, intent, content, payload_json, result_json, status, created_at, updated_at, processed_at
            FROM thread_commands
            WHERE thread_id = ? AND status IN ({placeholders})
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (thread_id, *active_statuses, limit),
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, row) for row in rows]

    def claim_next_command(self, thread_id: str) -> Optional[Dict[str, Any]]:
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                """
                SELECT id, thread_id, session_id, intent, content, payload_json, result_json, status, created_at, updated_at, processed_at
                FROM thread_commands
                WHERE thread_id = ? AND status = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (thread_id,),
            )
            row = cur.fetchone()
            desc = cur.description
            if row is None:
                conn.close()
                return None
            command_id = row[0]
            conn.execute(
                """
                UPDATE thread_commands
                SET status = 'in_progress', updated_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (now, command_id),
            )
            conn.commit()
            conn.close()
        payload = self._row_to_dict(desc, row)
        payload["status"] = "in_progress"
        payload["updated_at"] = now
        return payload

    def complete_command(
        self,
        command_id: str,
        *,
        status: str = "completed",
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                UPDATE thread_commands
                SET status = ?, result_json = ?, updated_at = ?, processed_at = ?
                WHERE id = ?
                """,
                (status, json.dumps(result or {}, default=str), now, now, command_id),
            )
            conn.commit()
            conn.close()

    def get_latest_snapshot(self, thread_id: str) -> Dict[str, Any]:
        conn = self._connect()
        cur = conn.execute(
            "SELECT last_snapshot_id, last_snapshot_json, pinned_entities_json, pinned_questions_json FROM investigation_threads WHERE id = ?",
            (thread_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return {}
        return self._build_snapshot_record(
            snapshot_id=row[0],
            snapshot_value=row[1],
            pinned_entities_value=row[2],
            pinned_questions_value=row[3],
        )

    def get_latest_authoritative_snapshot(self, thread_id: str) -> Dict[str, Any]:
        latest = self.get_latest_snapshot(thread_id)
        if not latest:
            return {}
        if latest.get("authority_scope") not in {"accepted", "published"}:
            return {}
        return latest

    def get_latest_accepted_snapshot(self, thread_id: str) -> Dict[str, Any]:
        """Compatibility wrapper for legacy callers.

        Prefer get_latest_authoritative_snapshot() so thread truth is not named as
        "accepted" when the authoritative snapshot is actually published.
        """
        return self.get_latest_authoritative_snapshot(thread_id)

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_threads (
                id TEXT PRIMARY KEY,
                case_id TEXT,
                root_session_id TEXT,
                last_session_id TEXT,
                thread_summary TEXT DEFAULT '',
                last_snapshot_id TEXT,
                last_snapshot_json TEXT DEFAULT '{}',
                pinned_entities_json TEXT DEFAULT '[]',
                pinned_questions_json TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS thread_messages (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                session_id TEXT,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (thread_id) REFERENCES investigation_threads(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS thread_commands (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                session_id TEXT,
                intent TEXT DEFAULT '',
                content TEXT NOT NULL,
                payload_json TEXT DEFAULT '{}',
                result_json TEXT DEFAULT '{}',
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                processed_at TEXT,
                FOREIGN KEY (thread_id) REFERENCES investigation_threads(id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_thread_messages_thread ON thread_messages(thread_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_thread_commands_thread ON thread_commands(thread_id, status, created_at)")
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    @classmethod
    def _build_snapshot_record(
        cls,
        *,
        snapshot_id: Any,
        snapshot_value: Any,
        pinned_entities_value: Any,
        pinned_questions_value: Any,
    ) -> Dict[str, Any]:
        snapshot = cls._json_load(snapshot_value, {})
        snapshot_contract = snapshot.get("snapshot_contract", {}) if isinstance(snapshot, dict) else {}
        lifecycle = ""
        if isinstance(snapshot_contract, dict):
            lifecycle = str(snapshot_contract.get("lifecycle") or "").strip().lower()
        if not lifecycle and isinstance(snapshot, dict):
            lifecycle = str(snapshot.get("snapshot_lifecycle") or "").strip().lower()
        authority_scope = "working"
        if lifecycle in {"accepted", "published"}:
            authority_scope = lifecycle
        elif isinstance(snapshot, dict):
            snapshot_state = str(snapshot.get("snapshot_state") or "").strip().lower()
            if snapshot_state == "accepted":
                authority_scope = "accepted"
        return {
            "snapshot_id": snapshot_id,
            "snapshot": snapshot,
            "authority_scope": authority_scope,
            "snapshot_lifecycle": lifecycle or None,
            "pinned_entities": cls._json_load(pinned_entities_value, []),
            "pinned_questions": cls._json_load(pinned_questions_value, []),
        }

    @staticmethod
    def _json_load(value: Any, default: Any) -> Any:
        if not value:
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default

    @classmethod
    def _row_to_dict(cls, description, row) -> Dict[str, Any]:
        cols = [item[0] for item in description]
        payload = dict(zip(cols, row))
        for key in (
            "last_snapshot_json",
            "pinned_entities_json",
            "pinned_questions_json",
            "metadata_json",
            "payload_json",
            "result_json",
        ):
            if key in payload:
                payload[key] = cls._json_load(payload.get(key), {} if key.endswith("_json") and key != "pinned_entities_json" and key != "pinned_questions_json" else [])
        if "last_snapshot_json" in payload:
            snapshot_payload = payload.pop("last_snapshot_json")
            payload["last_thread_snapshot"] = snapshot_payload
        if "pinned_entities_json" in payload:
            payload["pinned_entities"] = payload.pop("pinned_entities_json")
        if "pinned_questions_json" in payload:
            payload["pinned_questions"] = payload.pop("pinned_questions_json")
        if "metadata_json" in payload:
            payload["metadata"] = payload.pop("metadata_json")
        if "payload_json" in payload:
            payload["payload"] = payload.pop("payload_json")
        if "result_json" in payload:
            payload["result"] = payload.pop("result_json")
        return payload
