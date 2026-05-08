"""
Author: Ugur Ates
Agent API routes - Investigation management.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from src.agent.investigation_workdir import InvestigationWorkdirError, UnsafeWorkdirPathError

logger = logging.getLogger(__name__)
router = APIRouter()


class InvestigateRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="Investigation goal in natural language")
    case_id: Optional[str] = None
    playbook_id: Optional[str] = None
    agent_profile_id: Optional[str] = None
    workflow_id: Optional[str] = None
    max_steps: Optional[int] = Field(None, ge=1, le=1000, description="Maximum investigation steps")


class ApprovalRequest(BaseModel):
    approved: bool
    comment: str = ""


class WorkdirReviewRequest(BaseModel):
    decision: str = Field("pending", description="pending, accepted, needs_rework, or rejected")
    reviewer: str = "analyst"
    notes: str = ""


class WorkdirResumeStartRequest(BaseModel):
    goal: Optional[str] = None
    case_id: Optional[str] = None
    max_steps: Optional[int] = Field(None, ge=1, le=1000)


def _require_agent_loop(request: Request):
    loop = request.app.state.agent_loop
    if loop is None:
        raise HTTPException(503, "Agent loop not initialized")
    return loop


def _reject_unsafe_artifact_path(artifact_path: str) -> None:
    candidate = Path(str(artifact_path or ""))
    if candidate.is_absolute() or any(part in {"..", ""} for part in candidate.parts):
        raise HTTPException(400, "Unsafe artifact path")


def _require_workdir_service(request: Request):
    service = getattr(request.app.state, 'investigation_workdir_service', None)
    if service is None:
        raise HTTPException(503, "Investigation workdir service not initialized")
    return service


def _require_agent_store(request: Request):
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    return store


def _decorate_session_payload(session: Dict) -> Dict:
    """Flatten commonly used metadata into the top-level session payload."""
    payload = dict(session or {})
    metadata = payload.get('metadata')
    if not isinstance(metadata, dict):
        metadata = {}

    payload['session_id'] = payload.get('session_id') or payload.get('id')
    for field in (
        'max_steps',
        'current_step',
        'execution_mode',
        'pending_approval',
        'active_specialist',
        'specialist_team',
        'specialist_handoffs',
        'collaboration_mode',
        'lead_agent_profile_id',
        'chat_user_message',
        'chat_parent_session_id',
        'thread_id',
        'session_snapshot_id',
        'investigation_plan',
        'active_observations',
        'accepted_facts',
        'unresolved_questions',
        'memory_scope',
        'memory_kind',
        'memory_is_authoritative',
        'publication_scope',
        'authoritative_memory_scope',
        'memory_boundary',
        'chat_context_restored',
        'chat_context_restored_from_session_id',
        'chat_context_restored_from_thread_id',
        'chat_context_restored_snapshot_id',
        'chat_context_restored_memory_scope',
        'chat_context_restored_authoritative_memory_scope',
        'chat_context_restored_publication_scope',
        'chat_context_restored_memory_kind',
        'chat_context_restored_memory_is_authoritative',
        'chat_context_restored_counts',
        'chat_context_restored_reasoning_status',
        'chat_context_restored_source',
        'chat_context_restored_fact_family_schemas',
        'evidence_quality_summary',
        'reasoning_state',
        'entity_state',
        'evidence_state',
        'deterministic_decision',
        'deterministic_decision_output',
        'agentic_explanation',
        'agentic_explanation_output',
        'root_cause_assessment',
        'investigation_workdir',
        'investigation_dag',
        'adaptive_dag',
        'mutation_ledger',
    ):
        if payload.get(field) is None:
            if metadata.get(field) is not None:
                payload[field] = metadata.get(field)
            elif session.get(field) is not None:
                payload[field] = session.get(field)
    return payload


def _chat_history_messages(store, session: Dict) -> Dict[str, List[Dict]]:
    """Build the user/assistant turns that precede the current chat session."""
    chain: List[Dict] = []
    current = session if isinstance(session, dict) else None
    seen = set()

    while isinstance(current, dict):
        current_id = str(current.get('id') or current.get('session_id') or '').strip()
        if not current_id or current_id in seen:
            break
        seen.add(current_id)
        chain.append(current)

        metadata = current.get('metadata', {}) if isinstance(current.get('metadata'), dict) else {}
        parent_id = str(metadata.get('chat_parent_session_id') or '').strip()
        if not parent_id:
            break
        current = store.get_session(parent_id) if store is not None else None

    chain.reverse()
    history_messages: List[Dict] = []
    thread_session_ids = [
        str(item.get('id') or item.get('session_id') or '').strip()
        for item in chain
        if str(item.get('id') or item.get('session_id') or '').strip()
    ]

    for item in chain[:-1]:
        payload = _decorate_session_payload(item)
        prompt = str(payload.get('chat_user_message') or payload.get('goal') or '').strip()
        if prompt:
            history_messages.append({
                'role': 'user',
                'content': prompt,
                'session_id': payload.get('session_id'),
                'created_at': payload.get('created_at'),
            })

        findings = payload.get('findings', [])
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except json.JSONDecodeError:
                findings = []
        answer = ''
        if isinstance(findings, list):
            for finding in reversed(findings):
                if isinstance(finding, dict) and finding.get('type') == 'final_answer':
                    answer = str(finding.get('answer') or '').strip()
                    if answer:
                        break
        if not answer:
            answer = str(payload.get('summary') or '').strip()
        if answer:
            history_messages.append({
                'role': 'assistant',
                'content': answer,
                'session_id': payload.get('session_id'),
                'created_at': payload.get('completed_at') or payload.get('created_at'),
                'status': payload.get('status'),
            })

    return {
        'chat_history_messages': history_messages,
        'chat_thread_session_ids': thread_session_ids,
        'chat_root_session_id': thread_session_ids[0] if thread_session_ids else None,
    }


def _pending_approval_id(request: Request, session_id: str) -> Optional[str]:
    loop = getattr(request.app.state, 'agent_loop', None)
    if loop is not None:
        state = getattr(loop, '_active_sessions', {}).get(session_id)
        if state and state.pending_approval:
            return state.pending_approval.get('action', {}).get('approval_id')

    store = getattr(request.app.state, 'agent_store', None)
    if store is not None:
        session = store.get_session(session_id)
        if session:
            metadata = session.get('metadata', {}) if isinstance(session.get('metadata'), dict) else {}
            pending = metadata.get('pending_approval', {})
            if isinstance(pending, dict):
                return pending.get('approval_id')
    return None


@router.post('/investigate')
async def start_investigation(request: Request, body: InvestigateRequest):
    """Start a new agent investigation."""
    agent_loop = _require_agent_loop(request)
    session_id = await agent_loop.investigate(
        body.goal,
        body.case_id,
        body.playbook_id,
        max_steps=body.max_steps,
        metadata={
            "agent_profile_id": body.agent_profile_id,
            "workflow_id": body.workflow_id,
        },
    )
    payload = {
        "session_id": session_id,
        "status": "active",
        "goal": body.goal,
        "agent_profile_id": body.agent_profile_id,
        "workflow_id": body.workflow_id,
    }
    store = getattr(request.app.state, 'agent_store', None)
    if store is not None:
        session = store.get_session(session_id) or {}
        metadata = session.get('metadata', {}) if isinstance(session.get('metadata'), dict) else {}
        if metadata.get('investigation_workdir') is not None:
            payload["investigation_workdir"] = metadata.get('investigation_workdir')
    return payload


@router.get('/stats')
async def agent_stats(request: Request):
    """Get agent statistics."""
    store = _require_agent_store(request)
    stats = store.get_agent_stats()
    # Add tool count
    tool_registry = request.app.state.tool_registry
    if tool_registry:
        stats['registered_tools'] = len(tool_registry.list_tools())
    # Add MCP connection count
    mcp_client = request.app.state.mcp_client
    if mcp_client:
        status = mcp_client.get_connection_status()
        stats['mcp_servers'] = len(status)
        stats['mcp_connected'] = sum(1 for s in status.values() if s.get('connected'))
    profiles = getattr(request.app.state, 'agent_profiles', None)
    if profiles:
        stats['agent_profiles'] = profiles.count()
    workflows = getattr(request.app.state, 'workflow_registry', None)
    if workflows:
        stats['workflows'] = len(workflows.list_workflows())
    return stats


@router.get('/tools')
async def list_tools(request: Request, category: Optional[str] = None):
    """List all registered tools."""
    tool_registry = request.app.state.tool_registry
    if tool_registry is None:
        raise HTTPException(503, "Tool registry not initialized")
    tools = tool_registry.list_tools(category=category)
    return {"tools": [t.to_dict() for t in tools]}


@router.get('/action-connectors')
async def action_connector_catalog(request: Request):
    """Expose NextActionSignal-to-tool connector mappings and availability."""
    tool_registry = request.app.state.tool_registry
    if tool_registry is None:
        raise HTTPException(503, "Tool registry not initialized")
    catalog = tool_registry.action_connector_catalog() if hasattr(tool_registry, 'action_connector_catalog') else {"connectors": []}
    catalog["availability"] = [
        tool_registry.resolve_action_connector({"action_type": item.get("action_type")})
        for item in catalog.get("connectors", [])
        if isinstance(item, dict) and hasattr(tool_registry, 'resolve_action_connector')
    ]
    return catalog


@router.get('/profiles')
async def list_profiles(request: Request):
    """List specialist agent profiles."""
    profiles = getattr(request.app.state, 'agent_profiles', None)
    if profiles is None:
        raise HTTPException(503, "Agent profiles not initialized")
    return {"profiles": profiles.list_profiles()}


@router.get('/profiles/{profile_id}')
async def get_profile(request: Request, profile_id: str):
    """Return one specialist agent profile."""
    profiles = getattr(request.app.state, 'agent_profiles', None)
    if profiles is None:
        raise HTTPException(503, "Agent profiles not initialized")
    profile = profiles.get_profile(profile_id)
    if profile is None:
        raise HTTPException(404, "Agent profile not found")
    return profile.to_dict()


@router.get('/capabilities')
async def capability_catalog(request: Request):
    """Return the machine-readable orchestration and capability catalog."""
    catalog = getattr(request.app.state, 'capability_catalog', None)
    if catalog is None:
        raise HTTPException(503, "Capability catalog not initialized")
    return catalog.build_catalog(request.app)


@router.get('/memory/ioc/{ioc}')
async def recall_ioc(request: Request, ioc: str):
    """Check investigation memory for a previously analyzed IOC."""
    memory = request.app.state.investigation_memory
    if memory is None:
        raise HTTPException(503, "Investigation memory not initialized")

    cached = memory.recall_ioc(ioc)
    if cached:
        return {"cached": True, "ioc": ioc, "result": cached}
    return {"cached": False, "ioc": ioc, "message": f"No prior investigation found for {ioc}"}


@router.get('/memory/stats')
async def memory_stats(request: Request):
    """Get investigation memory statistics."""
    memory = request.app.state.investigation_memory
    if memory is None:
        raise HTTPException(503, "Investigation memory not initialized")

    summary = memory.get_pattern_summary()
    return summary


@router.get('/sandbox/status')
async def sandbox_status(request: Request):
    """Get sandbox environment status."""
    sandbox = request.app.state.sandbox_orchestrator
    if sandbox is None:
        raise HTTPException(503, "Sandbox orchestrator not initialized")

    status = sandbox.get_sandbox_status()
    return {"sandboxes": status}


@router.get('/correlation/{session_id}')
async def get_session_correlation(request: Request, session_id: str):
    """Get correlation analysis for a session's findings."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    correlation_engine = request.app.state.correlation_engine
    if correlation_engine is None:
        raise HTTPException(503, "Correlation engine not initialized")

    # Get session findings and correlate
    findings = session.get('findings', [])
    if isinstance(findings, str):
        import json
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []

    result = correlation_engine.correlate(findings)
    return {"session_id": session_id, "correlation": result}


@router.get('/sessions')
async def list_sessions(request: Request, limit: int = 50, status: Optional[str] = None):
    """List agent investigation sessions."""
    store = _require_agent_store(request)
    sessions = store.list_sessions(limit=limit, status=status)
    return {"sessions": [_decorate_session_payload(s) for s in sessions]}


@router.get('/connectors/availability')
async def connector_availability(request: Request):
    """Return stable availability for live/local action connector bridges."""
    registry = getattr(request.app.state, 'tool_registry', None)
    if registry is None or not hasattr(registry, 'connector_availability'):
        raise HTTPException(503, "Tool registry not initialized")
    return registry.connector_availability()


@router.get('/sessions/{session_id}/investigation-progress')
async def get_session_investigation_progress(request: Request, session_id: str):
    """Return agentic investigation progress extracted from persisted session metadata."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    provider = getattr(request.app.state, 'web_provider', None)
    if provider is None or not hasattr(provider, 'investigation_progress_from_session'):
        raise HTTPException(503, "Web data provider not initialized")
    return provider.investigation_progress_from_session(_decorate_session_payload(session))


@router.get('/sessions/{session_id}/context-ledger')
async def get_session_context_ledger(request: Request, session_id: str):
    """Return non-authoritative context ledger history and latest context pack metadata."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    metadata = session.get('metadata', {}) if isinstance(session.get('metadata'), dict) else {}
    latest_ledger = metadata.get('context_ledger_latest') if isinstance(metadata.get('context_ledger_latest'), dict) else {}
    ledgers = metadata.get('context_ledgers') if isinstance(metadata.get('context_ledgers'), list) else []
    latest_pack = metadata.get('context_pack_latest') if isinstance(metadata.get('context_pack_latest'), dict) else {}
    return {
        "schema_version": "context-ledger-history/v1",
        "session_id": session_id,
        "authority": "context_audit_metadata_non_authoritative",
        "authoritative_for_verdict": False,
        "latest_ledger": latest_ledger,
        "ledgers": [item for item in ledgers if isinstance(item, dict)],
        "latest_context_pack_summary": metadata.get('context_pack_summary_latest') if isinstance(metadata.get('context_pack_summary_latest'), dict) else {},
        "latest_context_pack": latest_pack,
        "latest_budget": metadata.get('context_budget_latest') if isinstance(metadata.get('context_budget_latest'), dict) else {},
        "workdir_artifacts": {
            "context_pack_latest": f"/api/agent/sessions/{session_id}/workdir/artifacts/context_pack_latest.json",
            "context_ledger_latest": f"/api/agent/sessions/{session_id}/workdir/artifacts/context_ledger_latest.json",
            "context_ledgers": f"/api/agent/sessions/{session_id}/workdir/artifacts/context_ledgers.json",
        },
    }


@router.get('/sessions/{session_id}')
async def get_session(request: Request, session_id: str):
    """Get session details with all steps."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    steps = store.get_steps(session_id)
    specialist_tasks = store.list_specialist_tasks(session_id)
    session = _decorate_session_payload(session)
    session['steps'] = steps
    session['specialist_tasks'] = specialist_tasks
    session.update(_chat_history_messages(store, session))
    # Include live state if available
    agent_loop = request.app.state.agent_loop
    if agent_loop:
        live_state = agent_loop.get_state(session_id)
        if live_state:
            session['live_state'] = live_state
    return session


def _session_workdir_id(store, service, session_id: str) -> tuple[Dict, str]:
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    metadata = session.get('metadata', {}) if isinstance(session.get('metadata'), dict) else {}
    workdir = metadata.get('investigation_workdir') if isinstance(metadata.get('investigation_workdir'), dict) else None
    investigation_id = str((workdir or {}).get('investigation_id') or metadata.get('investigation_id') or session_id)
    if not service.exists(investigation_id):
        raise HTTPException(404, "Investigation workdir not found")
    return session, investigation_id


@router.get('/sessions/{session_id}/workdir')
async def get_session_workdir_summary(request: Request, session_id: str):
    """Return safe workdir summary metadata for an agent session."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        return service.summarize(investigation_id)
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, f"Investigation workdir unavailable: {exc}") from exc


@router.get('/sessions/{session_id}/workdir/validation')
async def validate_session_workdir(request: Request, session_id: str):
    """Validate required workdir files and artifact integrity."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        return service.validate_manifest(investigation_id)
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, f"Investigation workdir validation unavailable: {exc}") from exc


@router.get('/sessions/{session_id}/workdir/review')
async def get_session_workdir_review_state(request: Request, session_id: str):
    """Return persisted analyst workdir review state."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        return service.get_review_state(investigation_id)
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put('/sessions/{session_id}/workdir/review')
async def update_session_workdir_review_state(request: Request, session_id: str, body: WorkdirReviewRequest):
    """Persist analyst review metadata without changing evidence/verdict files."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        review = service.update_review_state(
            investigation_id,
            decision=body.decision,
            reviewer=body.reviewer,
            notes=body.notes,
        )
        summary = service.summarize(investigation_id)
        store.update_session_metadata(session_id, {"investigation_workdir": summary}, merge=True)
        return review
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get('/sessions/{session_id}/workdir/resume')
async def get_session_workdir_resume_payload(request: Request, session_id: str):
    """Return a validated, non-authoritative workdir resume payload."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        return service.build_session_resume_payload(investigation_id)
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, f"Investigation workdir resume unavailable: {exc}") from exc


@router.post('/sessions/{session_id}/workdir/resume/start')
async def start_session_from_workdir_resume(request: Request, session_id: str, body: WorkdirResumeStartRequest):
    """Start a new agent session hydrated from validated workdir context."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    agent_loop = _require_agent_loop(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        result = await agent_loop.resume_from_workdir(
            investigation_id,
            goal=body.goal,
            case_id=body.case_id,
            max_steps=body.max_steps,
        )
        return result
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, f"Investigation workdir resume unavailable: {exc}") from exc


@router.get('/sessions/{session_id}/workdir/artifacts')
async def list_session_workdir_artifacts(request: Request, session_id: str):
    """List registered artifacts for an agent session workdir."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        index = service.read_json(investigation_id, "artifacts/index.json", default={"artifacts": []})
        artifacts = index.get('artifacts', []) if isinstance(index, dict) else []
        return {"session_id": session_id, "investigation_id": service.normalize_investigation_id(investigation_id), "artifacts": artifacts}
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get('/sessions/{session_id}/workdir/artifacts/{artifact_path:path}')
async def read_session_workdir_artifact(request: Request, session_id: str, artifact_path: str):
    """Read a safe text or JSON artifact from an agent session workdir."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    _reject_unsafe_artifact_path(artifact_path)
    _session, investigation_id = _session_workdir_id(store, service, session_id)
    suffix = Path(artifact_path).suffix.lower()
    if suffix not in {'.json', '.jsonl', '.md', '.txt'}:
        raise HTTPException(415, "Only text, markdown, JSON, and JSONL artifacts can be read inline")
    try:
        if suffix == '.json':
            return {
                "session_id": session_id,
                "investigation_id": service.normalize_investigation_id(investigation_id),
                "relative_path": artifact_path,
                "content_type": "application/json",
                "content": service.read_json(investigation_id, artifact_path),
            }
        media_type = "application/jsonl" if suffix == '.jsonl' else "text/markdown" if suffix == '.md' else "text/plain"
        return Response(service.read_text(investigation_id, artifact_path), media_type=f"{media_type}; charset=utf-8")
    except FileNotFoundError as exc:
        raise HTTPException(404, "Artifact not found") from exc
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except UnicodeDecodeError as exc:
        raise HTTPException(415, "Artifact is not valid UTF-8 text") from exc


@router.post('/sessions/{session_id}/workdir/archive')
async def archive_session_workdir(request: Request, session_id: str):
    """Create a zip archive for an agent session workdir and return its metadata."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        archive_path = service.archive(investigation_id)
        if archive_path is None:
            raise HTTPException(404, "Investigation workdir not found")
        summary = service.summarize(investigation_id)
        store.update_session_metadata(session_id, {"investigation_workdir": summary}, merge=True)
        return {"session_id": session_id, "investigation_id": summary.get('investigation_id'), "archive": {"filename": archive_path.name, "relative_path": archive_path.relative_to(service.get_path(investigation_id)).as_posix(), "size_bytes": archive_path.stat().st_size}}
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, f"Investigation workdir archive failed: {exc}") from exc


@router.get('/sessions/{session_id}/workdir/archive/download')
async def download_session_workdir_archive(request: Request, session_id: str):
    """Download the latest zip archive for an agent session workdir, creating one if needed."""
    service = _require_workdir_service(request)
    store = _require_agent_store(request)
    try:
        _session, investigation_id = _session_workdir_id(store, service, session_id)
        root = service.get_path(investigation_id)
        archive_dir = root / "_archive"
        archives = sorted(archive_dir.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True) if archive_dir.exists() else []
        archive_path = archives[0] if archives else service.archive(investigation_id)
        if archive_path is None or not archive_path.exists():
            raise HTTPException(404, "Investigation workdir archive not found")
        return FileResponse(str(archive_path), media_type="application/zip", filename=archive_path.name)
    except HTTPException:
        raise
    except (InvestigationWorkdirError, UnsafeWorkdirPathError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, f"Investigation workdir archive unavailable: {exc}") from exc


@router.get('/sessions/{session_id}/specialists')
async def get_session_specialists(request: Request, session_id: str):
    """Return explicit specialist execution units for a session."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return {"items": store.list_specialist_tasks(session_id)}


@router.delete('/sessions/{session_id}')
async def delete_session(request: Request, session_id: str):
    """Delete a persisted investigation session and related records."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    agent_loop = getattr(request.app.state, 'agent_loop', None)
    if agent_loop is not None:
        live_state = getattr(agent_loop, '_active_sessions', {}).get(session_id)
        if live_state is not None and not live_state.is_terminal():
            await agent_loop.cancel_session(session_id)
        getattr(agent_loop, '_active_sessions', {}).pop(session_id, None)
        getattr(agent_loop, '_approval_events', {}).pop(session_id, None)
        getattr(agent_loop, '_subscribers', {}).pop(session_id, None)

    deleted = store.delete_session(session_id)
    if not deleted:
        raise HTTPException(404, "Session not found")
    return {"status": "deleted", "session_id": session_id}


@router.post('/sessions/{session_id}/approve')
async def approve_action(request: Request, session_id: str, body: ApprovalRequest):
    """Approve or reject a pending action."""
    success = False
    approval_id = _pending_approval_id(request, session_id)
    governance_store = getattr(request.app.state, 'governance_store', None)
    if governance_store is not None and approval_id:
        governance_store.review_approval(
            approval_id,
            approved=body.approved,
            reviewer='analyst',
            comment=body.comment,
        )
    agent_loop = request.app.state.agent_loop
    if agent_loop is not None:
        if body.approved:
            success = await agent_loop.approve_action(session_id)
        else:
            success = await agent_loop.reject_action(session_id)

    if not success:
        playbook_engine = request.app.state.playbook_engine
        if playbook_engine is not None:
            success = await playbook_engine.resume_approval(session_id, body.approved)
    return {"success": success}


@router.post('/sessions/{session_id}/cancel')
async def cancel_session(request: Request, session_id: str):
    """Cancel an active investigation."""
    agent_loop = _require_agent_loop(request)
    await agent_loop.cancel_session(session_id)
    return {"status": "cancelled"}
