"""Governance persistence for approvals and AI decision logs."""

from __future__ import annotations

from collections import Counter
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
    explicit = os.environ.get('CABTA_GOVERNANCE_DB')
    if explicit:
        return Path(explicit)

    home_override = os.environ.get('CABTA_HOME')
    home_path = Path(home_override) if home_override else Path.home()
    return (runtime_cache_dir() if not home_override else home_path / 'cache') / 'governance.db'


_DEFAULT_DB = _default_db_path()


class GovernanceStore:
    """SQLite-backed store for approvals and AI decision logs."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        try:
            self._init_db()
            self._verify_writable()
        except (PermissionError, OSError, sqlite3.OperationalError) as exc:
            if db_path is not None:
                raise
            fallback = Path.cwd() / '.cabta-runtime' / 'governance.db'
            logger.warning(
                "[GOVERNANCE] Default DB %s unavailable (%s); falling back to %s",
                self._db_path,
                exc,
                fallback,
            )
            self._db_path = fallback
            self._init_db()
            self._verify_writable()

    def create_approval(
        self,
        *,
        session_id: str,
        action_type: str,
        tool_name: str,
        target: Any,
        rationale: str,
        evidence_refs: Optional[List[Dict[str, Any]]] = None,
        confidence: float = 0.0,
        case_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        approval_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO approvals
                   (id, session_id, case_id, workflow_id, action_type, tool_name,
                    target_json, rationale, evidence_refs_json, confidence,
                    status, metadata_json, requested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                (
                    approval_id,
                    session_id,
                    case_id,
                    workflow_id,
                    action_type,
                    tool_name,
                    json.dumps(target, default=str),
                    rationale,
                    json.dumps(evidence_refs or [], default=str),
                    float(confidence or 0.0),
                    json.dumps(metadata or {}, default=str),
                    now,
                ),
            )
            conn.commit()
            conn.close()
        return approval_id

    def list_approvals(
        self,
        *,
        status: Optional[str] = None,
        session_id: Optional[str] = None,
        case_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM approvals"
        clauses = []
        params: List[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY requested_at DESC LIMIT ?"
        params.append(limit)

        conn = self._connect()
        cur = conn.execute(query, tuple(params))
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, row) for row in rows]

    def get_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def get_pending_approval_for_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        approvals = self.list_approvals(status="pending", session_id=session_id, limit=1)
        return approvals[0] if approvals else None

    def review_approval(
        self,
        approval_id: str,
        *,
        approved: bool,
        reviewer: str = "analyst",
        comment: str = "",
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        status = "approved" if approved else "rejected"
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                """UPDATE approvals
                   SET status = ?, reviewed_at = ?, reviewer = ?, reviewer_comment = ?
                   WHERE id = ?""",
                (status, now, reviewer, comment, approval_id),
            )
            conn.commit()
            updated = cur.rowcount > 0
            conn.close()
        return updated

    def log_ai_decision(
        self,
        *,
        session_id: str,
        decision_type: str,
        summary: str,
        rationale: str = "",
        profile_id: Optional[str] = None,
        case_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        evidence_refs: Optional[List[Dict[str, Any]]] = None,
        confidence: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        decision_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO ai_decisions
                   (id, session_id, case_id, workflow_id, profile_id, decision_type,
                    summary, rationale, evidence_refs_json, confidence, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id,
                    session_id,
                    case_id,
                    workflow_id,
                    profile_id,
                    decision_type,
                    summary,
                    rationale,
                    json.dumps(evidence_refs or [], default=str),
                    float(confidence or 0.0),
                    json.dumps(metadata or {}, default=str),
                    now,
                ),
            )
            conn.commit()
            conn.close()
        return decision_id

    def list_ai_decisions(
        self,
        *,
        session_id: Optional[str] = None,
        case_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM ai_decisions"
        clauses = []
        params: List[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        if workflow_id:
            clauses.append("workflow_id = ?")
            params.append(workflow_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        conn = self._connect()
        cur = conn.execute(query, tuple(params))
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, row) for row in rows]

    def get_ai_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.execute("SELECT * FROM ai_decisions WHERE id = ?", (decision_id,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def add_decision_feedback(
        self,
        decision_id: str,
        *,
        feedback: str,
        reviewer: str = "analyst",
    ) -> bool:
        decision = self.get_ai_decision(decision_id)
        if not decision:
            return False

        self.record_decision_feedback(
            decision_id=decision_id,
            session_id=str(decision.get("session_id") or ""),
            case_id=decision.get("case_id"),
            workflow_id=decision.get("workflow_id"),
            feedback_type="decision_review",
            verdict="correct" if "correct" in str(feedback or "").lower() else "needs_review",
            target={"decision_id": decision_id},
            useful=None,
            comment=feedback,
            metadata={"legacy_feedback_text": feedback},
            reviewer=reviewer,
        )

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                """UPDATE ai_decisions
                   SET feedback = ?, feedback_reviewer = ?, feedback_at = ?
                   WHERE id = ?""",
                (feedback, reviewer, now, decision_id),
            )
            conn.commit()
            updated = cur.rowcount > 0
            conn.close()
        return updated

    def record_decision_feedback(
        self,
        *,
        decision_id: str,
        session_id: str,
        feedback_type: str,
        reviewer: str = "analyst",
        verdict: Optional[str] = None,
        target: Optional[Dict[str, Any]] = None,
        useful: Optional[bool] = None,
        comment: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        case_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> str:
        feedback_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO decision_feedback_events
                   (id, decision_id, session_id, case_id, workflow_id, feedback_type,
                    verdict, target_json, useful, comment, metadata_json, reviewer, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    feedback_id,
                    decision_id,
                    session_id,
                    case_id,
                    workflow_id,
                    feedback_type,
                    verdict,
                    json.dumps(target or {}, default=str),
                    None if useful is None else int(bool(useful)),
                    comment,
                    json.dumps(metadata or {}, default=str),
                    reviewer,
                    now,
                ),
            )
            conn.commit()
            conn.close()
        return feedback_id

    def list_decision_feedback(
        self,
        *,
        decision_id: Optional[str] = None,
        session_id: Optional[str] = None,
        case_id: Optional[str] = None,
        feedback_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM decision_feedback_events"
        clauses = []
        params: List[Any] = []
        if decision_id:
            clauses.append("decision_id = ?")
            params.append(decision_id)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        if feedback_type:
            clauses.append("feedback_type = ?")
            params.append(feedback_type)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        conn = self._connect()
        cur = conn.execute(query, tuple(params))
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, row) for row in rows]

    def governance_summary(
        self,
        *,
        session_id: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        approval_items = self.list_approvals(session_id=session_id, case_id=case_id, limit=1000)
        decision_items = self.list_ai_decisions(session_id=session_id, case_id=case_id, limit=1000)
        feedback_items = self.list_decision_feedback(session_id=session_id, case_id=case_id, limit=1000)

        approval_status_counts = Counter(str(item.get("status") or "unknown") for item in approval_items)
        decision_type_counts = Counter(str(item.get("decision_type") or "unknown") for item in decision_items)
        feedback_type_counts = Counter(str(item.get("feedback_type") or "unknown") for item in feedback_items)
        feedback_verdict_counts = Counter(str(item.get("verdict") or "unspecified") for item in feedback_items)

        return {
            "scope": {
                "session_id": session_id,
                "case_id": case_id,
            },
            "approvals": {
                "total": len(approval_items),
                "by_status": dict(approval_status_counts),
                "pending": approval_status_counts.get("pending", 0),
            },
            "ai_decisions": {
                "total": len(decision_items),
                "by_type": dict(decision_type_counts),
            },
            "decision_feedback": {
                "total": len(feedback_items),
                "by_type": dict(feedback_type_counts),
                "by_verdict": dict(feedback_verdict_counts),
            },
        }

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                id                 TEXT PRIMARY KEY,
                session_id         TEXT NOT NULL,
                case_id            TEXT,
                workflow_id        TEXT,
                action_type        TEXT NOT NULL,
                tool_name          TEXT NOT NULL,
                target_json        TEXT DEFAULT '{}',
                rationale          TEXT DEFAULT '',
                evidence_refs_json TEXT DEFAULT '[]',
                confidence         REAL DEFAULT 0,
                status             TEXT NOT NULL DEFAULT 'pending',
                reviewer           TEXT,
                reviewer_comment   TEXT DEFAULT '',
                metadata_json      TEXT DEFAULT '{}',
                requested_at       TEXT NOT NULL,
                reviewed_at        TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_decisions (
                id                 TEXT PRIMARY KEY,
                session_id         TEXT NOT NULL,
                case_id            TEXT,
                workflow_id        TEXT,
                profile_id         TEXT,
                decision_type      TEXT NOT NULL,
                summary            TEXT NOT NULL,
                rationale          TEXT DEFAULT '',
                evidence_refs_json TEXT DEFAULT '[]',
                confidence         REAL DEFAULT 0,
                metadata_json      TEXT DEFAULT '{}',
                created_at         TEXT NOT NULL,
                feedback           TEXT,
                feedback_reviewer  TEXT,
                feedback_at        TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decision_feedback_events (
                id            TEXT PRIMARY KEY,
                decision_id   TEXT NOT NULL,
                session_id    TEXT NOT NULL,
                case_id       TEXT,
                workflow_id   TEXT,
                feedback_type TEXT NOT NULL,
                verdict       TEXT,
                target_json   TEXT DEFAULT '{}',
                useful        INTEGER,
                comment       TEXT DEFAULT '',
                metadata_json TEXT DEFAULT '{}',
                reviewer      TEXT NOT NULL DEFAULT 'analyst',
                created_at    TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    def _verify_writable(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS governance_store_probe (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO governance_store_probe (id, created_at) VALUES (?, ?)",
                (uuid.uuid4().hex[:12], datetime.now(timezone.utc).isoformat()),
            )
            conn.rollback()
        finally:
            conn.close()

    @staticmethod
    def _json_load(value: Any, default: Any) -> Any:
        if not value:
            return default
        try:
            return json.loads(value)
        except Exception:
            return default

    def _row_to_dict(self, description, row) -> Dict[str, Any]:
        payload = dict(zip([d[0] for d in description], row))
        if "target_json" in payload:
            payload["target"] = self._json_load(payload.pop("target_json"), {})
        if "metadata_json" in payload:
            payload["metadata"] = self._json_load(payload.pop("metadata_json"), {})
        if "evidence_refs_json" in payload:
            payload["evidence_refs"] = self._json_load(payload.pop("evidence_refs_json"), [])
        return payload
