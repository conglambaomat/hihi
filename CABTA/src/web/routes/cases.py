"""
Author: Ugur Ates
Case Management API endpoints.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from ..models import CaseCreate, CaseNote, CaseStatusUpdate

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post('')
async def create_case(request: Request, payload: CaseCreate):
    """Create a new case."""
    store = request.app.state.case_store
    case_id = store.create_case(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
    )
    return {'id': case_id, 'message': f'Case created: {payload.title}'}


@router.get('')
async def list_cases(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
):
    """List all cases."""
    provider = request.app.state.web_provider
    cases = provider.list_cases(request.app, limit=limit, offset=offset, status=status)
    return {'items': cases}


@router.get('/{case_id}')
async def get_case(request: Request, case_id: str):
    """Get case details with linked analyses and notes."""
    provider = request.app.state.web_provider
    case = provider.get_case(request.app, case_id)
    if case is None:
        raise HTTPException(404, 'Case not found')
    return case


@router.patch('/{case_id}/status')
async def update_case_status(request: Request, case_id: str, payload: CaseStatusUpdate):
    """Update case status."""
    store = request.app.state.case_store
    ok = store.update_case_status(case_id, payload.status.value)
    if not ok:
        raise HTTPException(404, 'Case not found')
    return {'message': f'Status updated to {payload.status.value}'}


@router.post('/{case_id}/analyses')
async def link_analysis(request: Request, case_id: str, analysis_id: str):
    """Link an analysis to a case."""
    store = request.app.state.case_store
    ok = store.link_analysis(case_id, analysis_id)
    if not ok:
        raise HTTPException(400, 'Failed to link analysis')
    return {'message': 'Analysis linked to case'}


@router.get('/{case_id}/workflows')
async def list_case_workflows(request: Request, case_id: str):
    """List workflow runs linked to a case."""
    store = request.app.state.case_store
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, 'Case not found')
    workflow_service = getattr(request.app.state, 'workflow_service', None)
    if workflow_service is None:
        return {'items': case.get('workflows', [])}
    items = []
    for link in store.list_case_workflows(case_id):
        run = workflow_service.get_run(link['session_id'])
        items.append(run or link)
    return {'items': items}


@router.post('/{case_id}/notes')
async def add_note(request: Request, case_id: str, payload: CaseNote):
    """Add a note to a case."""
    store = request.app.state.case_store
    note_id = store.add_note(case_id, payload.content, payload.author)
    return {'id': note_id, 'message': 'Note added'}


@router.get('/{case_id}/timeline')
async def case_timeline(request: Request, case_id: str):
    """Return the case timeline reconstructed from real stored events."""
    intelligence = getattr(request.app.state, 'case_intelligence', None)
    if intelligence is None:
        raise HTTPException(503, 'Case intelligence not initialized')
    timeline = intelligence.build_timeline(case_id)
    if timeline is None:
        raise HTTPException(404, 'Case not found')
    return timeline


@router.get('/{case_id}/graph')
async def case_graph(request: Request, case_id: str):
    """Return the case graph reconstructed from real stored entities."""
    intelligence = getattr(request.app.state, 'case_intelligence', None)
    if intelligence is None:
        raise HTTPException(503, 'Case intelligence not initialized')
    graph = intelligence.build_graph(case_id)
    if graph is None:
        raise HTTPException(404, 'Case not found')
    return graph


@router.get('/{case_id}/root-cause')
async def case_root_cause(request: Request, case_id: str):
    """Return the latest stored root-cause assessment for a case."""
    store = request.app.state.case_store
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, 'Case not found')

    latest = None
    for event in reversed(case.get('events', [])):
        payload = event.get('payload', {}) if isinstance(event.get('payload'), dict) else {}
        root_cause = payload.get('root_cause_assessment', {}) if isinstance(payload, dict) else {}
        if isinstance(root_cause, dict) and root_cause.get('primary_root_cause'):
            latest = {
                'case_id': case_id,
                'event_id': event.get('id'),
                'event_type': event.get('event_type'),
                'recorded_at': event.get('created_at'),
                'root_cause_assessment': root_cause,
                'deterministic_decision': payload.get('deterministic_decision', {}),
            }
            break

    if latest is None:
        return {'case_id': case_id, 'root_cause_assessment': None}
    return latest


@router.get('/{case_id}/reasoning')
async def case_reasoning(request: Request, case_id: str):
    """Return the latest case-level reasoning rollup from linked workflow sessions."""
    intelligence = getattr(request.app.state, 'case_intelligence', None)
    if intelligence is None:
        raise HTTPException(503, 'Case intelligence not initialized')
    summary = intelligence.build_reasoning_summary(case_id)
    if summary is None:
        raise HTTPException(404, 'Case not found')
    return summary


@router.get('/{case_id}/approvals')
async def case_approvals(request: Request, case_id: str):
    """List approvals linked to a case."""
    governance = getattr(request.app.state, 'governance_store', None)
    if governance is None:
        raise HTTPException(503, 'Governance store not initialized')
    return {'items': governance.list_approvals(case_id=case_id, limit=200)}


@router.get('/{case_id}/decisions')
async def case_decisions(request: Request, case_id: str):
    """List AI decision log entries linked to a case."""
    governance = getattr(request.app.state, 'governance_store', None)
    if governance is None:
        raise HTTPException(503, 'Governance store not initialized')
    return {'items': governance.list_ai_decisions(case_id=case_id, limit=200)}
