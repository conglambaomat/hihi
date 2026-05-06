"""Local-first investigation workdir service for AISA agent workflows."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..utils.runtime_paths import runtime_home


SCHEMA_VERSION = "1.0"
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|authorization|bearer|session[_-]?cookie)", re.I)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|session[_-]?cookie)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)([?&](?:api[_-]?key|token|secret|password|session[_-]?cookie)=)[^&#\s]+"),
)


class InvestigationWorkdirError(Exception):
    """Base error for investigation workdir operations."""


class UnsafeWorkdirPathError(InvestigationWorkdirError):
    """Raised when a workdir-relative path escapes its investigation root."""


class CorruptWorkdirJsonError(InvestigationWorkdirError):
    """Raised when a workdir JSON file cannot be decoded."""


class InvestigationWorkdirService:
    """Manage safe per-investigation filesystem workdirs.

    The workdir is an audit/export mirror only. Deterministic AISA analyzers and
    scoring remain the authoritative source for verdicts and scores.
    """

    REQUIRED_DIRS = (
        "evidence",
        "evidence/query_results",
        "evidence/enrichments",
        "evidence/observations",
        "artifacts",
        "artifacts/evidence",
        "artifacts/enrichments",
        "artifacts/query-results",
        "artifacts/uploads",
        "artifacts/reports",
        "artifacts/scratch",
        "exports",
        "_archive",
    )
    REQUIRED_JSON_FILES = (
        "manifest.json",
        "plan.json",
        "state.json",
        "iocs.json",
        "entities.json",
        "timeline.json",
        "hypotheses.json",
        "evidence_graph.json",
        "deterministic_decision.json",
        "agentic_explanation.json",
        "artifacts/index.json",
        "review_state.json",
    )
    REQUIRED_TEXT_FILES = ("plan.md", "context.md", "review.md")
    REVIEW_DECISIONS = {"pending", "accepted", "needs_rework", "rejected"}

    def __init__(self, base_dir: str | Path | None = None, *, max_file_bytes: int | None = None):
        env_base = os.environ.get("AISA_INVESTIGATION_WORKDIR") or os.environ.get("CABTA_INVESTIGATION_WORKDIR")
        self.base_dir = Path(base_dir or env_base or (runtime_home() / "data" / "investigations")).expanduser()
        self.max_file_bytes = int(max_file_bytes or DEFAULT_MAX_FILE_BYTES)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._base_resolved = self.base_dir.resolve()

    def normalize_investigation_id(self, investigation_id: str) -> str:
        value = str(investigation_id or "").strip()
        if _ID_RE.match(value) and value not in {".", ".."}:
            return value
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-_")[:96]
        if not slug:
            slug = "investigation"
        digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
        return f"{slug}-{digest}"

    def create_or_get(
        self,
        investigation_id: str,
        *,
        case_id: str | None = None,
        session_id: str | None = None,
        thread_id: str | None = None,
    ) -> Path:
        safe_id = self.normalize_investigation_id(investigation_id)
        root = self.get_path(safe_id)
        first_create = not root.exists()
        root.mkdir(parents=True, exist_ok=True)
        for dirname in self.REQUIRED_DIRS:
            self._resolve(root, dirname).mkdir(parents=True, exist_ok=True)

        now = self._now()
        manifest_path = root / "manifest.json"
        if manifest_path.exists():
            manifest = self.read_json(safe_id, "manifest.json", default={})
            if not isinstance(manifest, dict):
                manifest = {}
            manifest.update({"updated_at": now})
            manifest.setdefault("created_at", now)
            manifest.setdefault("status", "active")
        else:
            manifest = {
                "schema_version": SCHEMA_VERSION,
                "product": "AISA",
                "investigation_id": safe_id,
                "case_id": case_id,
                "session_id": session_id,
                "thread_id": thread_id,
                "created_at": now,
                "updated_at": now,
                "status": "active",
                "runtime": {"local_first": True, "verdict_authority": "deterministic_aisa_scoring"},
            }
        for key, value in {"case_id": case_id, "session_id": session_id, "thread_id": thread_id}.items():
            if value is not None:
                manifest[key] = value
        self._write_json_path(manifest_path, manifest)

        defaults = {
            "plan.json": {"schema_version": SCHEMA_VERSION, "steps": []},
            "state.json": {
                "schema_version": SCHEMA_VERSION,
                "phase": "initialized",
                "last_step": 0,
                "latest_tool": None,
                "active_focus": None,
                "deterministic_decision_refs": [],
                "agentic_notes_refs": [],
                "open_questions": [],
            },
            "iocs.json": {"schema_version": SCHEMA_VERSION, "iocs": []},
            "entities.json": {"schema_version": SCHEMA_VERSION, "entities": {}},
            "timeline.json": {"schema_version": SCHEMA_VERSION, "events": []},
            "hypotheses.json": {"schema_version": SCHEMA_VERSION, "hypotheses": []},
            "evidence_graph.json": {"schema_version": SCHEMA_VERSION, "graph": {}},
            "deterministic_decision.json": {"schema_version": SCHEMA_VERSION, "verdict_boundary": "deterministic_aisa_scoring", "decision": {}},
            "agentic_explanation.json": {"schema_version": SCHEMA_VERSION, "verdict_boundary": "non_authoritative", "explanation": {}},
            "artifacts/index.json": {"schema_version": SCHEMA_VERSION, "artifacts": []},
            "review_state.json": self._default_review_state(),
        }
        for rel, payload in defaults.items():
            target = self._resolve(root, rel)
            if not target.exists():
                self._write_json_path(target, payload)
        for rel in self.REQUIRED_TEXT_FILES:
            target = self._resolve(root, rel)
            if not target.exists():
                target.write_text("", encoding="utf-8")
        log_path = root / "log.jsonl"
        if not log_path.exists():
            log_path.write_text("", encoding="utf-8")
        self.append_event(safe_id, "workdir_created" if first_create else "workdir_hydrated", {})
        return root

    def exists(self, investigation_id: str) -> bool:
        return self.get_path(investigation_id).exists()

    def get_path(self, investigation_id: str) -> Path:
        safe_id = self.normalize_investigation_id(investigation_id)
        path = (self.base_dir / safe_id).resolve()
        if not self._is_relative_to(path, self._base_resolved):
            raise UnsafeWorkdirPathError(f"Unsafe investigation path: {investigation_id}")
        return path

    def read_text(self, investigation_id: str, relative_path: str) -> str:
        path = self._resolve(self.get_path(investigation_id), relative_path)
        if path.stat().st_size > self.max_file_bytes:
            raise InvestigationWorkdirError(f"File exceeds max read size: {relative_path}")
        return path.read_text(encoding="utf-8")

    def write_text(self, investigation_id: str, relative_path: str, content: str, *, artifact_kind: str | None = None) -> Dict[str, Any]:
        data = str(content or "")
        if len(data.encode("utf-8")) > self.max_file_bytes:
            raise InvestigationWorkdirError(f"Content exceeds max write size: {relative_path}")
        root = self.get_path(investigation_id)
        path = self._resolve(root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(data, encoding="utf-8")
        tmp.replace(path)
        info = self._file_info(root, path)
        if artifact_kind:
            self.register_artifact(investigation_id, relative_path=relative_path, artifact_type=artifact_kind, source="agent_loop", metadata=info)
        return info

    def append_text(self, investigation_id: str, relative_path: str, content: str) -> Dict[str, Any]:
        root = self.get_path(investigation_id)
        path = self._resolve(root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(str(content or ""))
        return self._file_info(root, path)

    def read_json(self, investigation_id: str, relative_path: str, default: object | None = None) -> object:
        path = self._resolve(self.get_path(investigation_id), relative_path)
        if not path.exists():
            return default
        try:
            text = self.read_text(investigation_id, relative_path)
            return json.loads(text) if text.strip() else default
        except json.JSONDecodeError as exc:
            if default is not None:
                return default
            raise CorruptWorkdirJsonError(f"Corrupt JSON file: {relative_path}") from exc

    def write_json(self, investigation_id: str, relative_path: str, payload: object, *, artifact_kind: str | None = None) -> Dict[str, Any]:
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n"
        return self.write_text(investigation_id, relative_path, content, artifact_kind=artifact_kind)

    def refresh_artifact_integrity(self, investigation_id: str) -> Dict[str, Any]:
        """Refresh artifact index hashes, sizes, and timestamps."""
        root = self.get_path(investigation_id)
        index = self.read_json(investigation_id, "artifacts/index.json", default={"schema_version": SCHEMA_VERSION, "artifacts": []})
        if not isinstance(index, dict):
            index = {"schema_version": SCHEMA_VERSION, "artifacts": []}
        artifacts = []
        changed = False
        for raw in list(index.get("artifacts") or []):
            if not isinstance(raw, dict):
                changed = True
                continue
            entry = dict(raw)
            rel = str(entry.get("relative_path") or "").strip()
            if not rel:
                changed = True
                continue
            try:
                path = self._resolve(root, rel)
            except UnsafeWorkdirPathError:
                entry["integrity_status"] = "unsafe_path"
                artifacts.append(entry)
                changed = True
                continue
            if path.exists() and path.is_file():
                stat = path.stat()
                sha256 = self._sha256(path)
                updated_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                for key, value in {"size_bytes": stat.st_size, "sha256": sha256, "updated_at": updated_at, "integrity_status": "present"}.items():
                    if entry.get(key) != value:
                        entry[key] = value
                        changed = True
            else:
                if entry.get("integrity_status") != "missing":
                    entry["integrity_status"] = "missing"
                    changed = True
            artifacts.append(entry)
        index["schema_version"] = SCHEMA_VERSION
        index["artifacts"] = artifacts
        if changed:
            self._write_json_path(root / "artifacts" / "index.json", index)
        return index

    def register_artifact(
        self,
        investigation_id: str,
        *,
        relative_path: str,
        artifact_type: str,
        source: str,
        authoritative: bool = False,
        metadata: dict | None = None,
    ) -> Dict[str, Any]:
        root = self.get_path(investigation_id)
        path = self._resolve(root, relative_path)
        now = self._now()
        index = self.read_json(investigation_id, "artifacts/index.json", default={"schema_version": SCHEMA_VERSION, "artifacts": []})
        if not isinstance(index, dict):
            index = {"schema_version": SCHEMA_VERSION, "artifacts": []}
        artifacts = list(index.get("artifacts") or [])
        rel = path.relative_to(root).as_posix()
        existing = next((a for a in artifacts if isinstance(a, dict) and a.get("relative_path") == rel), None)
        entry = existing or {"id": uuid.uuid4().hex[:12], "created_at": now}
        entry.update({
            "relative_path": rel,
            "artifact_type": str(artifact_type or "scratch"),
            "source": str(source or "unknown"),
            "updated_at": now,
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "sha256": self._sha256(path) if path.exists() and path.is_file() else None,
            "mime_type": "application/json" if path.suffix.lower() == ".json" else "text/plain" if path.suffix.lower() in {".txt", ".md", ".jsonl"} else "application/octet-stream",
            "authoritative": bool(authoritative),
            "verdict_boundary": "deterministic_decision_ref" if authoritative else "non_authoritative",
            "metadata": metadata or {},
        })
        if existing is None:
            artifacts.append(entry)
        index["artifacts"] = artifacts
        self._write_json_path(root / "artifacts" / "index.json", index)
        self.append_event(investigation_id, "artifact_registered", {"relative_path": rel, "artifact_type": entry["artifact_type"]})
        return entry

    def persist_observation(self, investigation_id: str, *, step_number: int, tool_name: str, params: dict, result: dict) -> Dict[str, Any]:
        rel = f"evidence/observations/step-{int(step_number):04d}-{self._safe_name(tool_name)}.json"
        payload = {"schema_version": SCHEMA_VERSION, "step_number": step_number, "tool_name": tool_name, "params": self._redact(params), "result": result, "verdict_boundary": "deterministic_evidence_ref"}
        self.write_json(investigation_id, rel, payload)
        return self.register_artifact(investigation_id, relative_path=rel, artifact_type="tool_result", source=tool_name, authoritative=False, metadata={"step_number": step_number})

    def sync_state(self, investigation_id: str, *, phase: str, last_step: int, latest_tool: str | None = None, state: dict | None = None) -> None:
        payload = self.read_json(investigation_id, "state.json", default={})
        if not isinstance(payload, dict):
            payload = {}
        payload.update({"schema_version": SCHEMA_VERSION, "phase": phase, "last_step": last_step, "latest_tool": latest_tool, "updated_at": self._now()})
        if state:
            payload.update(state)
        self.write_json(investigation_id, "state.json", payload)
        self.append_event(investigation_id, "state_updated", {"phase": phase, "last_step": last_step})

    def append_event(self, investigation_id: str, event_type: str, payload: dict | None = None) -> None:
        root = self.get_path(investigation_id)
        manifest = self.read_json(investigation_id, "manifest.json", default={})
        if not isinstance(manifest, dict):
            manifest = {}
        event = {
            "ts": self._now(),
            "product": "AISA",
            "investigation_id": self.normalize_investigation_id(investigation_id),
            "case_id": manifest.get("case_id"),
            "session_id": manifest.get("session_id"),
            "event_type": str(event_type),
            "payload": self._redact(payload or {}),
        }
        with (root / "log.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n")

    def get_review_state(self, investigation_id: str) -> Dict[str, Any]:
        payload = self.read_json(investigation_id, "review_state.json", default=None)
        if not isinstance(payload, dict):
            payload = self._default_review_state()
            self.write_json(investigation_id, "review_state.json", payload)
        return payload

    def update_review_state(
        self,
        investigation_id: str,
        *,
        decision: str,
        reviewer: str = "",
        notes: str = "",
    ) -> Dict[str, Any]:
        decision = str(decision or "pending").strip().lower()
        if decision not in self.REVIEW_DECISIONS:
            raise InvestigationWorkdirError(f"Review decision must be one of: {', '.join(sorted(self.REVIEW_DECISIONS))}")
        state = self.get_review_state(investigation_id)
        now = self._now()
        history = list(state.get("history") or [])
        event = {
            "decision": decision,
            "reviewer": str(reviewer or "").strip() or "analyst",
            "notes": str(notes or ""),
            "reviewed_at": now,
            "verdict_boundary": "analyst_review_non_authoritative_metadata",
        }
        history.append(event)
        state.update({
            "schema_version": SCHEMA_VERSION,
            "decision": decision,
            "reviewer": event["reviewer"],
            "notes": event["notes"],
            "updated_at": now,
            "history": history[-50:],
            "verdict_boundary": "does_not_modify_canonical_evidence_or_deterministic_verdict",
        })
        self.write_json(investigation_id, "review_state.json", state)
        self.append_event(investigation_id, "review_state_updated", {"decision": decision, "reviewer": event["reviewer"]})
        return state

    def generate_review(self, investigation_id: str, *, summary: str = "", status: str = "completed") -> str:
        manifest = self.read_json(investigation_id, "manifest.json", default={})
        state = self.read_json(investigation_id, "state.json", default={})
        review_state = self.get_review_state(investigation_id)
        review = (
            f"# AISA Investigation Review\n\n"
            f"- Investigation ID: {self.normalize_investigation_id(investigation_id)}\n"
            f"- Status: {status}\n"
            f"- Case ID: {(manifest or {}).get('case_id') if isinstance(manifest, dict) else None}\n"
            f"- Session ID: {(manifest or {}).get('session_id') if isinstance(manifest, dict) else None}\n"
            f"- Verdict authority: deterministic AISA scoring remains authoritative.\n"
            f"- Last step: {(state or {}).get('last_step') if isinstance(state, dict) else None}\n"
            f"- Analyst decision: {review_state.get('decision', 'pending')}\n"
            f"- Reviewer: {review_state.get('reviewer') or 'unassigned'}\n"
            f"- Review state file: review_state.json\n\n"
            f"## Summary\n\n{summary or 'No terminal summary recorded.'}\n\n"
            f"## Analyst Review Notes\n\n{review_state.get('notes') or '- Validate deterministic evidence before closure. - Treat agentic explanation artifacts as non-authoritative interpretation.'}\n\n"
            f"## Review Boundary\n\nAnalyst feedback is persisted as review metadata and does not change canonical evidence or deterministic verdict files.\n"
        )
        self.write_text(investigation_id, "review.md", review)
        self.append_event(investigation_id, "review_generated", {"status": status})
        return review

    def summarize(self, investigation_id: str) -> Dict[str, Any]:
        root = self.get_path(investigation_id)
        manifest = self.read_json(investigation_id, "manifest.json", default={})
        index = self.read_json(investigation_id, "artifacts/index.json", default={})
        events = (root / "log.jsonl").read_text(encoding="utf-8").splitlines() if (root / "log.jsonl").exists() else []
        last_event = None
        for line in reversed(events):
            if line.strip():
                try:
                    last_event = json.loads(line)
                except json.JSONDecodeError:
                    last_event = {"event_type": "corrupt_event"}
                break
        validation = self.validate_manifest(investigation_id)
        review_state = self.get_review_state(investigation_id) if root.exists() else self._default_review_state()
        return {
            "investigation_id": self.normalize_investigation_id(investigation_id),
            "path": str(root),
            "manifest": manifest if isinstance(manifest, dict) else {},
            "artifact_count": len((index or {}).get("artifacts", [])) if isinstance(index, dict) else 0,
            "disk_usage_bytes": self._disk_usage(root),
            "last_event_type": last_event.get("event_type") if isinstance(last_event, dict) else None,
            "validation_status": validation.get("status"),
            "validation_error_count": len(validation.get("errors", [])),
            "review_state": {"decision": review_state.get("decision"), "reviewer": review_state.get("reviewer"), "updated_at": review_state.get("updated_at")},
            "verdict_boundary": "deterministic_scoring_remains_authoritative",
        }

    def validate_manifest(self, investigation_id: str) -> Dict[str, Any]:
        """Validate required layout, JSON readability, and artifact integrity."""
        safe_id = self.normalize_investigation_id(investigation_id)
        root = self.get_path(safe_id)
        errors: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []
        checked_artifacts: List[Dict[str, Any]] = []
        if not root.exists():
            return {"schema_version": SCHEMA_VERSION, "investigation_id": safe_id, "status": "missing", "valid": False, "errors": [{"code": "missing_workdir", "path": safe_id}], "warnings": [], "artifacts": []}
        for dirname in self.REQUIRED_DIRS:
            path = self._resolve(root, dirname)
            if not path.exists() or not path.is_dir():
                errors.append({"code": "missing_required_dir", "path": dirname})
        for rel in self.REQUIRED_JSON_FILES:
            path = self._resolve(root, rel)
            if not path.exists():
                errors.append({"code": "missing_required_json", "path": rel})
                continue
            try:
                parsed = self.read_json(safe_id, rel)
                if not isinstance(parsed, dict):
                    warnings.append({"code": "json_not_object", "path": rel})
                elif rel == "manifest.json" and parsed.get("schema_version") != SCHEMA_VERSION:
                    errors.append({"code": "schema_version_mismatch", "path": rel, "expected": SCHEMA_VERSION, "actual": parsed.get("schema_version")})
            except CorruptWorkdirJsonError:
                errors.append({"code": "corrupt_json", "path": rel})
        for rel in self.REQUIRED_TEXT_FILES:
            path = self._resolve(root, rel)
            if not path.exists() or not path.is_file():
                errors.append({"code": "missing_required_text", "path": rel})
        index = self.read_json(safe_id, "artifacts/index.json", default={"artifacts": []})
        for raw in (index.get("artifacts", []) if isinstance(index, dict) else []):
            if not isinstance(raw, dict):
                warnings.append({"code": "invalid_artifact_entry"})
                continue
            rel = str(raw.get("relative_path") or "")
            artifact_status = {"relative_path": rel, "status": "unknown"}
            try:
                path = self._resolve(root, rel)
            except UnsafeWorkdirPathError:
                errors.append({"code": "artifact_unsafe_path", "path": rel})
                artifact_status["status"] = "unsafe_path"
                checked_artifacts.append(artifact_status)
                continue
            if not path.exists() or not path.is_file():
                errors.append({"code": "artifact_missing", "path": rel})
                artifact_status["status"] = "missing"
                checked_artifacts.append(artifact_status)
                continue
            stat = path.stat()
            actual_sha256 = self._sha256(path)
            expected_sha256 = raw.get("sha256")
            expected_size = raw.get("size_bytes")
            artifact_status.update({"status": "ok", "sha256": actual_sha256, "size_bytes": stat.st_size, "updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()})
            if expected_sha256 and expected_sha256 != actual_sha256:
                errors.append({"code": "artifact_hash_mismatch", "path": rel, "expected": expected_sha256, "actual": actual_sha256})
                artifact_status["status"] = "hash_mismatch"
            if isinstance(expected_size, int) and expected_size != stat.st_size:
                errors.append({"code": "artifact_size_mismatch", "path": rel, "expected": expected_size, "actual": stat.st_size})
                artifact_status["status"] = "size_mismatch"
            checked_artifacts.append(artifact_status)
        status = "valid" if not errors else "invalid"
        return {"schema_version": SCHEMA_VERSION, "investigation_id": safe_id, "status": status, "valid": not errors, "errors": errors, "warnings": warnings, "artifacts": checked_artifacts, "verdict_boundary": "workdir_validation_only_deterministic_scoring_remains_authoritative"}

    def build_resume_snapshot(self, investigation_id: str) -> Dict[str, Any]:
        """Load a validated, non-authoritative resume snapshot from a workdir."""
        safe_id = self.normalize_investigation_id(investigation_id)
        root = self.get_path(safe_id)
        if not root.exists():
            raise FileNotFoundError(f"Investigation workdir not found: {safe_id}")
        self.refresh_artifact_integrity(safe_id)
        validation = self.validate_manifest(safe_id)
        if not validation.get("valid"):
            raise InvestigationWorkdirError("Workdir validation failed; cannot build trusted resume payload")
        artifact_index = self.read_json(safe_id, "artifacts/index.json", default={"artifacts": []})
        artifacts = artifact_index.get("artifacts", []) if isinstance(artifact_index, dict) else []
        artifact_hashes = [
            {"relative_path": a.get("relative_path"), "sha256": a.get("sha256"), "size_bytes": a.get("size_bytes"), "updated_at": a.get("updated_at")}
            for a in artifacts
            if isinstance(a, dict)
        ]
        snapshot = {
            "schema_version": SCHEMA_VERSION,
            "investigation_id": safe_id,
            "manifest": self.read_json(safe_id, "manifest.json", default={}),
            "state": self.read_json(safe_id, "state.json", default={}),
            "reasoning_state": self.read_json(safe_id, "hypotheses.json", default={}),
            "entity_state": self.read_json(safe_id, "entities.json", default={}),
            "evidence_state": self.read_json(safe_id, "evidence_graph.json", default={}),
            "deterministic_decision": self.read_json(safe_id, "deterministic_decision.json", default={}),
            "agentic_explanation": self.read_json(safe_id, "agentic_explanation.json", default={}),
            "artifact_index": artifact_index,
            "artifact_hashes": artifact_hashes,
            "validation": validation,
            "review_state": self.get_review_state(safe_id),
            "verdict_boundary": "deterministic_scoring_remains_authoritative",
            "resume_authority": "workdir_mirror_non_authoritative",
            "resume_warning": "Workdir content is historical context only; fresh AISA tools must re-validate before authoritative verdict changes.",
        }
        self.validate_resume_snapshot(snapshot)
        return snapshot

    def validate_resume_snapshot(self, snapshot: Dict[str, Any]) -> bool:
        if not isinstance(snapshot, dict):
            raise InvestigationWorkdirError("Resume snapshot must be a JSON object")
        if snapshot.get("schema_version") != SCHEMA_VERSION:
            raise InvestigationWorkdirError("Unsupported resume snapshot schema version")
        if not snapshot.get("investigation_id"):
            raise InvestigationWorkdirError("Resume snapshot missing investigation_id")
        if not isinstance(snapshot.get("manifest"), dict) or not isinstance(snapshot.get("state"), dict):
            raise InvestigationWorkdirError("Resume snapshot manifest/state must be objects")
        if snapshot.get("resume_authority") != "workdir_mirror_non_authoritative":
            raise InvestigationWorkdirError("Resume snapshot authority marker is invalid")
        return True

    def build_session_resume_payload(self, investigation_id: str) -> Dict[str, Any]:
        snapshot = self.build_resume_snapshot(investigation_id)
        manifest = snapshot.get("manifest", {}) if isinstance(snapshot.get("manifest"), dict) else {}
        state = snapshot.get("state", {}) if isinstance(snapshot.get("state"), dict) else {}
        source_hashes = list(snapshot.get("artifact_hashes") or [])
        resume_goal = f"Resume AISA investigation from workdir {snapshot.get('investigation_id')}. Re-validate historical workdir evidence with fresh tools before changing deterministic verdicts."
        state_payload = {
            "investigation_plan": snapshot.get("manifest", {}).get("investigation_plan") if isinstance(snapshot.get("manifest"), dict) else None,
            "reasoning_state": snapshot.get("reasoning_state") if isinstance(snapshot.get("reasoning_state"), dict) else {},
            "entity_state": snapshot.get("entity_state") if isinstance(snapshot.get("entity_state"), dict) else {},
            "evidence_state": snapshot.get("evidence_state") if isinstance(snapshot.get("evidence_state"), dict) else {},
            "unresolved_questions": state.get("open_questions", []) if isinstance(state, dict) else [],
            "workdir_historical_decision": snapshot.get("deterministic_decision"),
            "workdir_agentic_explanation": snapshot.get("agentic_explanation"),
        }
        source_case_id = str(manifest.get("case_id") or "").strip() or None
        source_session_id = str(manifest.get("session_id") or "").strip() or None
        source_thread_id = str(manifest.get("thread_id") or "").strip() or None
        return {
            "session_id": source_session_id,
            "thread_id": source_thread_id,
            "case_id": source_case_id,
            "source_session_id": source_session_id,
            "source_workdir_id": snapshot.get("investigation_id"),
            "source_case_id": source_case_id,
            "investigation_id": snapshot.get("investigation_id"),
            "phase": state.get("phase"),
            "last_step": state.get("last_step"),
            "resume_goal": resume_goal,
            "metadata": {
                "resume_mode": "workdir_deep_resume",
                "source_workdir_id": snapshot.get("investigation_id"),
                "source_session_id": source_session_id,
                "source_case_id": source_case_id,
                "source_workdir_investigation_id": snapshot.get("investigation_id"),
                "source_workdir_session_id": source_session_id,
                "source_workdir_thread_id": source_thread_id,
                "source_artifact_hashes": source_hashes,
                "workdir_resume_warning": snapshot.get("resume_warning"),
                "deterministic_verdict_boundary": "workdir_decision_is_historical_context_only_until_fresh_tool_validation",
                "resume_authority": "workdir_mirror_non_authoritative",
            },
            "state_payload": state_payload,
            "snapshot": snapshot,
            "verdict_boundary": "deterministic_scoring_remains_authoritative",
            "resume_authority": "workdir_mirror_non_authoritative",
        }

    def list_workdirs(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for child in sorted(self.base_dir.iterdir() if self.base_dir.exists() else []):
            if not child.is_dir():
                continue
            try:
                summary = self.summarize(child.name)
                summary["updated_at"] = (summary.get("manifest") or {}).get("updated_at") or datetime.fromtimestamp(child.stat().st_mtime, timezone.utc).isoformat()
                items.append(summary)
            except Exception:
                continue
        return items

    def list_stale_workdirs(self, *, retention_days: int = 30, keep_latest: int = 100) -> List[Dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, int(retention_days)))
        items = sorted(self.list_workdirs(), key=lambda item: str(item.get("updated_at") or ""), reverse=True)
        stale: List[Dict[str, Any]] = []
        for index, item in enumerate(items):
            updated_raw = str(item.get("updated_at") or "")
            try:
                updated = datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
            except ValueError:
                updated = datetime.fromtimestamp(self.get_path(str(item.get("investigation_id"))).stat().st_mtime, timezone.utc)
            if index >= max(0, int(keep_latest)) or updated < cutoff:
                stale.append(item)
        return stale

    def apply_retention(self, *, retention_days: int = 30, keep_latest: int = 100, action: str = "archive", dry_run: bool = True) -> Dict[str, Any]:
        action = str(action or "archive").lower()
        if action not in {"archive", "delete", "prune"}:
            raise InvestigationWorkdirError("Retention action must be archive, delete, or prune")
        stale = self.list_stale_workdirs(retention_days=retention_days, keep_latest=keep_latest)
        results: List[Dict[str, Any]] = []
        for item in stale:
            investigation_id = str(item.get("investigation_id"))
            result = {"investigation_id": investigation_id, "action": action, "dry_run": dry_run}
            if not dry_run:
                if action == "archive":
                    archive_path = self.archive(investigation_id)
                    result["archive"] = archive_path.name if archive_path else None
                elif action == "delete":
                    shutil.rmtree(self.get_path(investigation_id))
                    result["deleted"] = True
                elif action == "prune":
                    archive_path = self.archive(investigation_id)
                    shutil.rmtree(self.get_path(investigation_id), ignore_errors=True)
                    result["archive"] = archive_path.name if archive_path else None
                    result["deleted"] = True
            results.append(result)
        return {"stale_count": len(stale), "action": action, "dry_run": dry_run, "results": results}

    def archive(self, investigation_id: str) -> Path | None:
        root = self.get_path(investigation_id)
        if not root.exists():
            return None
        self.refresh_artifact_integrity(investigation_id)
        validation = self.validate_manifest(investigation_id)
        self.write_json(investigation_id, "artifacts/reports/integrity-summary.json", validation, artifact_kind="integrity_summary")
        archive_dir = self._resolve(root, "_archive")
        archive_dir.mkdir(exist_ok=True)
        archive_path = archive_dir / f"{self.normalize_investigation_id(investigation_id)}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in root.rglob("*"):
                if not item.is_file():
                    continue
                rel = item.relative_to(root).as_posix()
                name = item.name.lower()
                if rel.startswith("_archive/") or name.endswith(".tmp") or (name.startswith(".") and ".tmp" in name):
                    continue
                zf.write(item, rel)
        made_path = archive_path.resolve()
        if not self._is_relative_to(made_path, root.resolve()):
            raise UnsafeWorkdirPathError("Archive escaped investigation root")
        manifest = self.read_json(investigation_id, "manifest.json", default={})
        if isinstance(manifest, dict):
            manifest.update({"status": "archived", "updated_at": self._now()})
            self.write_json(investigation_id, "manifest.json", manifest)
        self.append_event(investigation_id, "workdir_archived", {"archive_path": archive_path.name})
        return made_path

    def _resolve(self, root: Path, relative_path: str) -> Path:
        rel = Path(str(relative_path or ""))
        if rel.is_absolute():
            raise UnsafeWorkdirPathError(f"Absolute paths are not allowed: {relative_path}")
        path = (root / rel).resolve()
        if not self._is_relative_to(path, root.resolve()):
            raise UnsafeWorkdirPathError(f"Path escapes investigation root: {relative_path}")
        return path

    def _write_json_path(self, path: Path, payload: object) -> None:
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n"
        if len(content.encode("utf-8")) > self.max_file_bytes:
            raise InvestigationWorkdirError(f"JSON exceeds max write size: {path.name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)

    @staticmethod
    def _default_review_state() -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": "pending",
            "reviewer": "",
            "notes": "",
            "created_at": now,
            "updated_at": now,
            "history": [],
            "verdict_boundary": "does_not_modify_canonical_evidence_or_deterministic_verdict",
        }

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _is_relative_to(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _disk_usage(root: Path) -> int:
        total = 0
        for item in root.rglob("*"):
            try:
                if item.is_file():
                    total += item.stat().st_size
            except OSError:
                continue
        return total

    @staticmethod
    def _file_info(root: Path, path: Path) -> Dict[str, Any]:
        return {"relative_path": path.relative_to(root).as_posix(), "size_bytes": path.stat().st_size, "sha256": InvestigationWorkdirService._sha256(path)}

    @staticmethod
    def _safe_name(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "artifact")).strip(".-_")[:80] or "artifact"

    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): ("[REDACTED]" if _SECRET_KEY_RE.search(str(k)) else cls._redact(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._redact(v) for v in value]
        if isinstance(value, str):
            redacted = value
            for pattern in _SENSITIVE_VALUE_PATTERNS:
                redacted = pattern.sub(lambda match: match.group(1) + "[REDACTED]", redacted)
            return redacted
        return value
