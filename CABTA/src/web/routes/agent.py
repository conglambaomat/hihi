"""
Author: Ugur Ates
Agent API routes - Investigation management.
"""

import json
import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter()


class InvestigateRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="Investigation goal in natural language")
    case_id: Optional[str] = None
    playbook_id: Optional[str] = None
    agent_profile_id: Optional[str] = None
    workflow_id: Optional[str] = None
    max_steps: Optional[int] = Field(None, ge=1, le=500, description="Maximum investigation steps")


class ApprovalRequest(BaseModel):
    approved: bool
    comment: str = ""


def _require_agent_loop(request: Request):
    loop = request.app.state.agent_loop
    if loop is None:
        raise HTTPException(503, "Agent loop not initialized")
    return loop


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
    return {
        "session_id": session_id,
        "status": "active",
        "goal": body.goal,
        "agent_profile_id": body.agent_profile_id,
        "workflow_id": body.workflow_id,
    }


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
