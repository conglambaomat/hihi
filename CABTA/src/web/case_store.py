"""
Author: Ugur Ates
Case Management Store - SQLite-backed case tracking.

Tables:
- cases: id, title, description, severity, status, created_at, updated_at
- case_analyses: case_id, analysis_id, linked_at
- case_notes: id, case_id, content, author, created_at
"""

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.runtime_paths import runtime_cache_dir

logger = logging.getLogger(__name__)

_DEFAULT_DB = runtime_cache_dir() / 'cases.db'


class CaseStore:
    """SQLite-backed case management."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------ #
    # Cases
    # ------------------------------------------------------------------ #

    def create_case(
        self,
        title: str,
        description: str = '',
        severity: str = 'medium',
    ) -> str:
        case_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO cases (id, title, description, severity, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'Open', ?, ?)""",
                (case_id, title, description, severity, now, now),
            )
            conn.commit()
            conn.close()
        self.add_event(
            case_id,
            event_type='case_created',
            title=f"Case created: {title}",
            payload={'severity': severity},
            created_at=now,
        )
        logger.info(f"[CASE] Created case {case_id}: {title}")
        return case_id

    def get_case(self, case_id: str) -> Optional[Dict]:
        conn = self._connect()
        cur = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cur.fetchone()
        if row is None:
            conn.close()
            return None
        case = self._row_to_dict(cur.description, row)

        # Attach analyses
        cur2 = conn.execute(
            "SELECT analysis_id, linked_at FROM case_analyses WHERE case_id = ?",
            (case_id,),
        )
        case['analyses'] = [
            {'analysis_id': r[0], 'linked_at': r[1]} for r in cur2.fetchall()
        ]

        curw = conn.execute(
            "SELECT session_id, workflow_id, linked_at FROM case_workflows WHERE case_id = ? ORDER BY linked_at",
            (case_id,),
        )
        case['workflows'] = [
            {'session_id': r[0], 'workflow_id': r[1], 'linked_at': r[2]}
            for r in curw.fetchall()
        ]

        # Attach notes
        cur3 = conn.execute(
            "SELECT id, content, author, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        )
        case['notes'] = [
            {'id': r[0], 'content': r[1], 'author': r[2], 'created_at': r[3]}
            for r in cur3.fetchall()
        ]
        cur4 = conn.execute(
            "SELECT id, event_type, title, payload_json, created_at FROM case_events WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        )
        case['events'] = [
            {
                'id': r[0],
                'event_type': r[1],
                'title': r[2],
                'payload': self._json_load(r[3], {}),
                'created_at': r[4],
            }
            for r in cur4.fetchall()
        ]
        conn.close()
        return case

    def list_cases(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict]:
        conn = self._connect()
        if status:
            cur = conn.execute(
                """SELECT c.*,
                          (SELECT COUNT(*) FROM case_analyses WHERE case_id=c.id) as analysis_count,
                          (SELECT COUNT(*) FROM case_notes WHERE case_id=c.id) as note_count,
                          (SELECT COUNT(*) FROM case_workflows WHERE case_id=c.id) as workflow_count,
                          (SELECT COUNT(*) FROM case_events WHERE case_id=c.id) as event_count
                   FROM cases c WHERE c.status = ?
                   ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
                (status, limit, offset),
            )
        else:
            cur = conn.execute(
                """SELECT c.*,
                          (SELECT COUNT(*) FROM case_analyses WHERE case_id=c.id) as analysis_count,
                          (SELECT COUNT(*) FROM case_notes WHERE case_id=c.id) as note_count,
                          (SELECT COUNT(*) FROM case_workflows WHERE case_id=c.id) as workflow_count,
                          (SELECT COUNT(*) FROM case_events WHERE case_id=c.id) as event_count
                   FROM cases c
                   ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            )
        rows = cur.fetchall()
        conn.close()
        return [self._row_to_dict(cur.description, r) for r in rows]

    def update_case_status(self, case_id: str, status: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, case_id),
            )
            conn.commit()
            updated = cur.rowcount > 0
            conn.close()
        if updated:
            self.add_event(
                case_id,
                event_type='case_status_updated',
                title=f"Case status updated to {status}",
                payload={'status': status},
                created_at=now,
            )
        return updated

    # ------------------------------------------------------------------ #
    # Case-Analysis linking
    # ------------------------------------------------------------------ #

    def link_analysis(self, case_id: str, analysis_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        linked = False
        with self._lock:
            try:
                conn = self._connect()
                conn.execute(
                    "INSERT OR IGNORE INTO case_analyses (case_id, analysis_id, linked_at) VALUES (?, ?, ?)",
                    (case_id, analysis_id, now),
                )
                conn.commit()
                conn.close()
                linked = True
            except Exception:
                return False
        if linked:
            self.add_event(
                case_id,
                event_type='analysis_linked',
                title=f"Analysis linked: {analysis_id}",
                payload={'analysis_id': analysis_id},
                created_at=now,
            )
        return linked

    def link_workflow(self, case_id: str, session_id: str, workflow_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        linked = False
        with self._lock:
            try:
                conn = self._connect()
                conn.execute(
                    "INSERT OR IGNORE INTO case_workflows (case_id, session_id, workflow_id, linked_at) VALUES (?, ?, ?, ?)",
                    (case_id, session_id, workflow_id, now),
                )
                conn.execute(
                    "UPDATE cases SET updated_at = ? WHERE id = ?",
                    (now, case_id),
                )
                conn.commit()
                conn.close()
                linked = True
            except Exception:
                return False
        if linked:
            self.add_event(
                case_id,
                event_type='workflow_linked',
                title=f"Workflow linked: {workflow_id}",
                payload={'session_id': session_id, 'workflow_id': workflow_id},
                created_at=now,
            )
        return linked

    def list_case_workflows(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute(
            "SELECT session_id, workflow_id, linked_at FROM case_workflows WHERE case_id = ? ORDER BY linked_at DESC",
            (case_id,),
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {'session_id': row[0], 'workflow_id': row[1], 'linked_at': row[2]}
            for row in rows
        ]

    # ------------------------------------------------------------------ #
    # Notes
    # ------------------------------------------------------------------ #

    def add_note(self, case_id: str, content: str, author: str = 'analyst') -> str:
        note_id = uuid.uuid4().hex[:10]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO case_notes (id, case_id, content, author, created_at) VALUES (?, ?, ?, ?, ?)",
                (note_id, case_id, content, author, now),
            )
            # Touch updated_at on parent case
            conn.execute(
                "UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id)
            )
            conn.commit()
            conn.close()
        self.add_event(
            case_id,
            event_type='note_added',
            title='Case note added',
            payload={'note_id': note_id, 'author': author},
            created_at=now,
        )
        return note_id

    def add_event(
        self,
        case_id: str,
        event_type: str,
        title: str,
        payload: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
    ) -> str:
        event_id = uuid.uuid4().hex[:10]
        timestamp = created_at or datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO case_events (id, case_id, event_type, title, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, case_id, event_type, title, json.dumps(payload or {}, default=str), timestamp),
            )
            conn.execute(
                "UPDATE cases SET updated_at = ? WHERE id = ?",
                (timestamp, case_id),
            )
            conn.commit()
            conn.close()
        return event_id

    def list_events(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute(
            "SELECT id, event_type, title, payload_json, created_at FROM case_events WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {
                'id': row[0],
                'event_type': row[1],
                'title': row[2],
                'payload': self._json_load(row[3], {}),
                'created_at': row[4],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------ #
    # DB setup
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity    TEXT DEFAULT 'medium',
                status      TEXT DEFAULT 'Open',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_analyses (
                case_id     TEXT NOT NULL,
                analysis_id TEXT NOT NULL,
                linked_at   TEXT NOT NULL,
                PRIMARY KEY (case_id, analysis_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id         TEXT PRIMARY KEY,
                case_id    TEXT NOT NULL,
                content    TEXT NOT NULL,
                author     TEXT DEFAULT 'analyst',
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_workflows (
                case_id     TEXT NOT NULL,
                session_id  TEXT NOT NULL,
                workflow_id TEXT NOT NULL,
                linked_at   TEXT NOT NULL,
                PRIMARY KEY (case_id, session_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_events (
                id         TEXT PRIMARY KEY,
                case_id    TEXT NOT NULL,
                event_type TEXT NOT NULL,
                title      TEXT NOT NULL,
                payload_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    @staticmethod
    def _row_to_dict(description, row) -> Dict:
        return dict(zip([d[0] for d in description], row))

    @staticmethod
    def _json_load(value: Any, default: Any) -> Any:
        if not value:
            return default
        try:
            return json.loads(value)
        except Exception:
            return default
