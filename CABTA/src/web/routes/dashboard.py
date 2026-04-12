"""
Author: Ugur Ates
Dashboard API endpoints.
"""

import logging
from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get('/stats')
async def get_stats(request: Request):
    """Get dashboard statistics."""
    provider = request.app.state.web_provider
    return provider.get_dashboard_stats(request.app)


@router.get('/recent')
async def get_recent(request: Request, limit: int = 10):
    """Get recent analyses."""
    provider = request.app.state.web_provider
    jobs = provider.list_jobs(request.app, limit=limit)
    return {'items': jobs}


@router.get('/sources')
async def get_sources(request: Request):
    """Get TI source health status."""
    provider = request.app.state.web_provider
    return {
        'sources': provider.get_sources(request.app),
        'summary': provider.source_health_summary(request.app),
        'mode': provider.app_mode(),
    }
