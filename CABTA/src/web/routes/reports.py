"""
Author: Ugur Ates
Report API endpoints.
"""

import json
import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get('/{analysis_id}/json')
async def get_report_json(request: Request, analysis_id: str):
    """Get raw JSON report."""
    provider = request.app.state.web_provider
    job = provider.get_job(request.app, analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')
    return JSONResponse(content=job)


@router.get('/{analysis_id}/html')
async def get_report_html(request: Request, analysis_id: str):
    """Get HTML report."""
    provider = request.app.state.web_provider
    job = provider.get_job(request.app, analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        'report_view.html',
        provider.build_template_context(request.app, request, job=job),
    )


@router.get('/{analysis_id}/mitre')
async def get_mitre_layer(request: Request, analysis_id: str):
    """Get MITRE ATT&CK Navigator layer JSON."""
    provider = request.app.state.web_provider
    job = provider.get_job(request.app, analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    result = job.get('result') or {}
    techniques = result.get('mitre_techniques', []) or result.get('mitre_mapping', [])

    # Build Navigator layer
    layer = {
        'name': f'CABTA Analysis {analysis_id}',
        'versions': {'attack': '14', 'navigator': '4.9', 'layer': '4.5'},
        'domain': 'enterprise-attack',
        'description': f'Auto-generated from analysis {analysis_id}',
        'techniques': [
            {
                'techniqueID': t.get('technique_id', ''),
                'tactic': t.get('tactic', '').lower().replace(' ', '-'),
                'color': '#e60d0d',
                'comment': t.get('technique_name', t.get('name', '')),
                'enabled': True,
            }
            for t in techniques
        ],
    }
    return JSONResponse(content=layer)
