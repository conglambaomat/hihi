"""
Agent Store - SQLite persistence for agent sessions, steps, MCP connections and playbooks.

Follows the AnalysisManager / CaseStore pattern (threading.Lock + _init_db + _connect + _row_to_dict).
"""

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.runtime_paths import runtime_cache_dir

logger = logging.getLogger(__name__)

def _default_db_path() -> Path:
    explicit = os.environ.get('CABTA_AGENT_DB')
    if explicit:
        return Path(explicit)

    home_override = os.environ.get('CABTA_HOME')
    home_path = Path(home_override) if home_override else Path.home()
    return (runtime_cache_dir() if not home_override else home_path / 'cache') / 'agent.db'


_DEFAULT_DB = _default_db_path()


class AgentStore:
    """SQLite-backed persistence for the autonomous agent."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        try:
            self._init_db()
            self._verify_writable()
        except (PermissionError, OSError, sqlite3.OperationalError) as exc:
            if db_path is not None:
                raise
            fallback = Path.cwd() / '.cabta-runtime' / 'agent.db'
            logger.warning(
                "[AGENT] Default agent DB %s unavailable (%s); falling back to %s",
                self._db_path,
                exc,
                fallback,
            )
            self._db_path = fallback
            self._init_db()
            self._verify_writable()

    # ================================================================== #
    #  Sessions
    # ================================================================== #

    def create_session(
        self,
        goal: str,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a new agent session. Returns session ID."""
        session_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(metadata or {}, default=str)

        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO agent_sessions
                   (id, case_id, goal, status, playbook_id, created_at, findings, metadata)
                   VALUES (?, ?, ?, 'active', ?, ?, '[]', ?)""",
                (session_id, case_id, goal, playbook_id, now, metadata_json),
            )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Created session {session_id}: {goal[:80]}")
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Retrieve a single session by ID."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM agent_sessions WHERE id = ?", (session_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def list_sessions(
        self, limit: int = 50, status: Optional[str] = None,
    ) -> List[Dict]:
        """List sessions, newest first, with optional status filter."""
        conn = self._connect()
        if status:
            cur = conn.execute(
                """SELECT * FROM agent_sessions WHERE status = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (status, limit),
            )
        else:
            cur = conn.execute(
                "SELECT * FROM agent_sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    def update_session_status(
        self,
        session_id: str,
        status: str,
        summary: Optional[str] = None,
    ) -> None:
        """Update session status and optionally set the summary."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            if summary is not None:
                conn.execute(
                    """UPDATE agent_sessions
                       SET status = ?, summary = ?, completed_at = ?
                       WHERE id = ?""",
                    (status, summary, now, session_id),
                )
            else:
                conn.execute(
                    "UPDATE agent_sessions SET status = ? WHERE id = ?",
                    (status, session_id),
                )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Session {session_id} -> {status}")

    def update_session_findings(
        self, session_id: str, findings: List[Dict],
    ) -> None:
        """Persist the current findings list."""
        findings_json = json.dumps(findings, default=str)
        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE agent_sessions SET findings = ? WHERE id = ?",
                (findings_json, session_id),
            )
            conn.commit()
            conn.close()

    def update_session_metadata(
        self,
        session_id: str,
        metadata: Dict[str, Any],
        merge: bool = True,
    ) -> None:
        """Persist session metadata, optionally merging with existing keys."""
        if not isinstance(metadata, dict):
            metadata = {}

        with self._lock:
            conn = self._connect()
            new_metadata = dict(metadata)

            if merge:
                cur = conn.execute(
                    "SELECT metadata FROM agent_sessions WHERE id = ?",
                    (session_id,),
                )
                row = cur.fetchone()
                existing = {}
                if row and row[0]:
                    try:
                        parsed = json.loads(row[0])
                        if isinstance(parsed, dict):
                            existing = parsed
                    except json.JSONDecodeError:
                        existing = {}
                new_metadata = {**existing, **metadata}

            conn.execute(
                "UPDATE agent_sessions SET metadata = ? WHERE id = ?",
                (json.dumps(new_metadata, default=str), session_id),
            )
            conn.commit()
            conn.close()

    # ================================================================== #
    #  Steps
    # ================================================================== #

    def add_step(
        self,
        session_id: str,
        step_number: int,
        step_type: str,
        content: str,
        tool_name: Optional[str] = None,
        tool_params: Optional[str] = None,
        tool_result: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> str:
        """Record an agent step. Returns step ID."""
        step_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO agent_steps
                   (id, session_id, step_number, step_type, content,
                    tool_name, tool_params, tool_result, duration_ms, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (step_id, session_id, step_number, step_type, content,
                 tool_name, tool_params, tool_result, duration_ms, now),
            )
            conn.commit()
            conn.close()

        return step_id

    def get_steps(self, session_id: str) -> List[Dict]:
        """Return all steps for a session ordered by step_number."""
        conn = self._connect()
        cur = conn.execute(
            """SELECT * FROM agent_steps
               WHERE session_id = ?
               ORDER BY step_number ASC, created_at ASC""",
            (session_id,),
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    def delete_session(self, session_id: str) -> bool:
        """Delete one session and all persisted child records."""
        deleted = False
        with self._lock:
            conn = self._connect()
            conn.execute(
                "DELETE FROM specialist_tasks WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM agent_steps WHERE session_id = ?",
                (session_id,),
            )
            cur = conn.execute(
                "DELETE FROM agent_sessions WHERE id = ?",
                (session_id,),
            )
            deleted = cur.rowcount > 0
            conn.commit()
            conn.close()

        if deleted:
            logger.info(f"[AGENT] Deleted session: {session_id}")
        return deleted

    # ================================================================== #
    #  Specialist Tasks
    # ================================================================== #

    def upsert_specialist_task(
        self,
        *,
        session_id: str,
        workflow_id: Optional[str],
        profile_id: str,
        phase_order: int,
        status: str,
        summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create or update one explicit specialist execution record."""
        task_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(metadata or {}, default=str)

        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                """SELECT id, started_at, completed_at FROM specialist_tasks
                   WHERE session_id = ? AND profile_id = ? AND phase_order = ?""",
                (session_id, profile_id, phase_order),
            )
            row = cur.fetchone()
            if row:
                task_id = row[0]
                started_at = row[1] or (now if status in {"active", "completed", "failed"} else None)
                completed_at = row[2]
                if status in {"completed", "failed", "skipped"}:
                    completed_at = completed_at or now
                elif status == "active":
                    completed_at = None
                conn.execute(
                    """UPDATE specialist_tasks
                       SET workflow_id = ?, status = ?, summary = ?, metadata_json = ?,
                           started_at = ?, completed_at = ?, updated_at = ?
                       WHERE id = ?""",
                    (
                        workflow_id,
                        status,
                        summary,
                        metadata_json,
                        started_at,
                        completed_at,
                        now,
                        task_id,
                    ),
                )
            else:
                started_at = now if status in {"active", "completed", "failed"} else None
                completed_at = now if status in {"completed", "failed", "skipped"} else None
                conn.execute(
                    """INSERT INTO specialist_tasks
                       (id, session_id, workflow_id, profile_id, phase_order, status,
                        summary, metadata_json, created_at, updated_at, started_at, completed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        task_id,
                        session_id,
                        workflow_id,
                        profile_id,
                        phase_order,
                        status,
                        summary,
                        metadata_json,
                        now,
                        now,
                        started_at,
                        completed_at,
                    ),
                )
            conn.commit()
            conn.close()

        return {
            "id": task_id,
            "session_id": session_id,
            "workflow_id": workflow_id,
            "profile_id": profile_id,
            "phase_order": phase_order,
            "status": status,
            "summary": summary,
            "metadata": metadata or {},
        }

    def list_specialist_tasks(self, session_id: str) -> List[Dict]:
        """Return specialist execution units for one investigation session."""
        conn = self._connect()
        cur = conn.execute(
            """SELECT * FROM specialist_tasks
               WHERE session_id = ?
               ORDER BY phase_order ASC, created_at ASC""",
            (session_id,),
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, row) for row in rows]

    # ================================================================== #
    #  MCP Connections
    # ================================================================== #

    def save_mcp_connection(
        self, name: str, transport: str, config: Dict,
    ) -> str:
        """Upsert an MCP server connection. Returns connection ID."""
        conn_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        config_json = json.dumps(config, default=str)

        with self._lock:
            conn = self._connect()
            # Try update first
            cur = conn.execute(
                """UPDATE mcp_connections
                   SET transport = ?, config_json = ?
                   WHERE name = ?""",
                (transport, config_json, name),
            )
            if cur.rowcount == 0:
                conn.execute(
                    """INSERT INTO mcp_connections
                       (id, name, transport, config_json, status, created_at)
                       VALUES (?, ?, ?, ?, 'disconnected', ?)""",
                    (conn_id, name, transport, config_json, now),
                )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Saved MCP connection: {name} ({transport})")
        return conn_id

    def list_mcp_connections(self) -> List[Dict]:
        """Return all registered MCP connections."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM mcp_connections ORDER BY name ASC",
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    def update_mcp_status(
        self,
        name: str,
        status: str,
        tools: Optional[List[Dict]] = None,
    ) -> None:
        """Update connection status and optionally refresh tool list."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            if tools is not None:
                tools_json = json.dumps(tools, default=str)
                conn.execute(
                    """UPDATE mcp_connections
                       SET status = ?, last_connected = ?, tools_json = ?
                       WHERE name = ?""",
                    (status, now, tools_json, name),
                )
            else:
                conn.execute(
                    """UPDATE mcp_connections
                       SET status = ?, last_connected = ?
                       WHERE name = ?""",
                    (status, now, name),
                )
            conn.commit()
            conn.close()

    def delete_mcp_connection(self, name: str) -> None:
        """Remove an MCP connection by name."""
        with self._lock:
            conn = self._connect()
            conn.execute(
                "DELETE FROM mcp_connections WHERE name = ?", (name,),
            )
            conn.commit()
            conn.close()
        logger.info(f"[AGENT] Deleted MCP connection: {name}")

    # ================================================================== #
    #  Playbooks
    # ================================================================== #

    def save_playbook(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        trigger_type: str = 'manual',
    ) -> str:
        """Create or update a playbook. Returns playbook ID."""
        playbook_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        steps_json = json.dumps(steps, default=str)

        with self._lock:
            conn = self._connect()
            # Try update first
            cur = conn.execute(
                """UPDATE playbooks
                   SET description = ?, trigger_type = ?, steps_json = ?, updated_at = ?
                   WHERE name = ?""",
                (description, trigger_type, steps_json, now, name),
            )
            if cur.rowcount == 0:
                conn.execute(
                    """INSERT INTO playbooks
                       (id, name, description, trigger_type, steps_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (playbook_id, name, description, trigger_type, steps_json, now, now),
                )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Saved playbook: {name}")
        return playbook_id

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Retrieve a single playbook by ID."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM playbooks WHERE id = ?", (playbook_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def list_playbooks(self) -> List[Dict]:
        """List all playbooks."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM playbooks ORDER BY updated_at DESC",
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    # ================================================================== #
    #  Statistics
    # ================================================================== #

    def get_agent_stats(self) -> Dict:
        """Return aggregate statistics across sessions and steps."""
        conn = self._connect()

        cur = conn.execute(
            """SELECT
                 COUNT(*) AS total,
                 SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
                 SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                 SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
               FROM agent_sessions"""
        )
        row = cur.fetchone()
        total_sessions = row[0] or 0
        active_sessions = row[1] or 0
        completed_sessions = row[2] or 0
        failed_sessions = row[3] or 0

        cur2 = conn.execute("SELECT COUNT(*) FROM agent_steps")
        total_steps = cur2.fetchone()[0] or 0

        cur3 = conn.execute("SELECT COUNT(*) FROM specialist_tasks")
        total_specialist_tasks = cur3.fetchone()[0] or 0

        conn.close()

        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "completed_sessions": completed_sessions,
            "failed_sessions": failed_sessions,
            "total_steps": total_steps,
            "total_specialist_tasks": total_specialist_tasks,
        }

    # ================================================================== #
    #  DB helpers
    # ================================================================== #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()

        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_sessions (
                id           TEXT PRIMARY KEY,
                case_id      TEXT,
                goal         TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'active',
                playbook_id  TEXT,
                created_at   TEXT NOT NULL,
                completed_at TEXT,
                summary      TEXT,
                findings     TEXT DEFAULT '[]',
                metadata     TEXT DEFAULT '{}'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_steps (
                id           TEXT PRIMARY KEY,
                session_id   TEXT NOT NULL,
                step_number  INTEGER NOT NULL,
                step_type    TEXT NOT NULL,
                content      TEXT NOT NULL,
                tool_name    TEXT,
                tool_params  TEXT,
                tool_result  TEXT,
                duration_ms  INTEGER,
                created_at   TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_connections (
                id             TEXT PRIMARY KEY,
                name           TEXT NOT NULL UNIQUE,
                transport      TEXT NOT NULL,
                config_json    TEXT NOT NULL,
                status         TEXT DEFAULT 'disconnected',
                last_connected TEXT,
                tools_json     TEXT DEFAULT '[]',
                created_at     TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS playbooks (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL UNIQUE,
                description  TEXT,
                trigger_type TEXT DEFAULT 'manual',
                steps_json   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS specialist_tasks (
                id           TEXT PRIMARY KEY,
                session_id   TEXT NOT NULL,
                workflow_id  TEXT,
                profile_id   TEXT NOT NULL,
                phase_order  INTEGER NOT NULL,
                status       TEXT NOT NULL DEFAULT 'planned',
                summary      TEXT DEFAULT '',
                metadata_json TEXT DEFAULT '{}',
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                started_at   TEXT,
                completed_at TEXT,
                UNIQUE(session_id, profile_id, phase_order),
                FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
            )
        """)

        # Indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_status ON agent_sessions(status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_created ON agent_sessions(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_steps_session ON agent_steps(session_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_specialist_tasks_session ON specialist_tasks(session_id)"
        )

        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    def _verify_writable(self) -> None:
        """Ensure the current SQLite path accepts writes, not just reads."""
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_store_probe (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO agent_store_probe (id, created_at) VALUES (?, ?)",
                (uuid.uuid4().hex[:12], datetime.now(timezone.utc).isoformat()),
            )
            conn.rollback()
        finally:
            conn.close()

    @staticmethod
    def _row_to_dict(description, row) -> Dict:
        cols = [d[0] for d in description]
        d = dict(zip(cols, row))
        # Parse known JSON columns
        for key in ('findings', 'metadata', 'config_json', 'tools_json', 'steps_json', 'metadata_json'):
            if d.get(key) and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except json.JSONDecodeError:
                    pass
        if 'metadata_json' in d and 'metadata' not in d:
            d['metadata'] = d.get('metadata_json', {})
        return d
