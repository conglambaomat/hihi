"""
Author: Ugur Ates
Configuration and health check endpoints.
"""

import logging
import platform
import sys
from datetime import datetime, timezone
from copy import deepcopy

import aiohttp
from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()
DEFAULT_APPROVAL_TOOLS = ['sandbox_submit']
API_KEY_CATALOG = [
    {'key': 'virustotal', 'label': 'VirusTotal', 'placeholder': 'API key'},
    {'key': 'abuseipdb', 'label': 'AbuseIPDB', 'placeholder': 'API key'},
    {'key': 'shodan', 'label': 'Shodan', 'placeholder': 'API key'},
    {'key': 'alienvault', 'label': 'AlienVault OTX', 'placeholder': 'API key'},
    {'key': 'greynoise', 'label': 'GreyNoise', 'placeholder': 'API key'},
    {'key': 'urlscan', 'label': 'URLScan.io', 'placeholder': 'API key'},
    {'key': 'censys_id', 'label': 'Censys API ID', 'placeholder': 'API ID'},
    {'key': 'censys_secret', 'label': 'Censys API Secret', 'placeholder': 'API secret'},
    {'key': 'pulsedive', 'label': 'Pulsedive', 'placeholder': 'API key'},
    {'key': 'criminalip', 'label': 'Criminal IP', 'placeholder': 'API key'},
    {'key': 'ipqualityscore', 'label': 'IPQualityScore', 'placeholder': 'API key'},
    {'key': 'phishtank', 'label': 'PhishTank', 'placeholder': 'API key'},
    {'key': 'ip2proxy', 'label': 'IP2Proxy', 'placeholder': 'API key'},
    {'key': 'hybridanalysis', 'label': 'Hybrid Analysis', 'placeholder': 'API key'},
    {'key': 'anyrun', 'label': 'ANY.RUN', 'placeholder': 'API key'},
    {'key': 'triage', 'label': 'Triage', 'placeholder': 'API key'},
    {'key': 'threatzone', 'label': 'ThreatZone', 'placeholder': 'API key'},
    {'key': 'joesandbox', 'label': 'Joe Sandbox', 'placeholder': 'API key'},
    {'key': 'abusech', 'label': 'abuse.ch / ThreatFox', 'placeholder': 'Auth-Key'},
]


def _normalize_default_sandbox(value: str) -> str:
    raw = str(value or '').strip().lower()
    if raw == 'subprocess':
        return 'vm'
    if raw in ('', 'disabled'):
        return 'none'
    return raw or 'none'


def _mask_secret_value(value):
    if value and isinstance(value, str) and len(value) > 8:
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    return value


def _runtime_llm_config(request: Request):
    """Return the active LLM config from app state."""
    config = dict(getattr(request.app.state, 'config', {}) or {})
    llm_cfg = config.get('llm', {}) if isinstance(config, dict) else {}
    api_keys = config.get('api_keys', {}) if isinstance(config, dict) else {}
    provider = str(llm_cfg.get('provider') or 'ollama').strip().lower() or 'ollama'
    return llm_cfg, api_keys, provider


async def _build_llm_health_result(request: Request, endpoint: str = 'http://localhost:11434'):
    """Return provider-aware LLM health diagnostics."""
    llm_cfg, api_keys, provider = _runtime_llm_config(request)
    result = {
        'provider': provider,
        'status': 'degraded',
        'available': False,
        'configured_model': '',
        'endpoint': '',
        'uses_local_runtime': provider == 'ollama',
        'message': None,
        'error': None,
        # Legacy compatibility fields used by older frontend code.
        'ollama_running': None,
        'model_available': False,
        'available_models': [],
    }

    if provider == 'groq':
        has_key = bool(api_keys.get('groq') or llm_cfg.get('api_key'))
        result.update({
            'configured_model': llm_cfg.get('groq_model', llm_cfg.get('model', 'openai/gpt-oss-20b')),
            'endpoint': str(llm_cfg.get('groq_endpoint', llm_cfg.get('base_url', 'https://api.groq.com/openai/v1'))).rstrip('/'),
            'available': has_key,
            'model_available': has_key,
            'status': 'configured' if has_key else 'degraded',
            'message': (
                'Groq is configured for AISA agent and analyst-assist workflows.'
                if has_key else
                'Groq is selected as the LLM provider, but the API key is missing.'
            ),
            'error': None if has_key else 'Groq API key not configured.',
        })
        return result

    if provider == 'anthropic':
        has_key = bool(api_keys.get('anthropic'))
        result.update({
            'configured_model': llm_cfg.get('anthropic_model', llm_cfg.get('model', 'claude-sonnet-4-20250514')),
            'endpoint': 'https://api.anthropic.com/v1',
            'available': has_key,
            'model_available': has_key,
            'status': 'configured' if has_key else 'degraded',
            'message': (
                'Anthropic is configured for AISA agent and analyst-assist workflows.'
                if has_key else
                'Anthropic is selected as the LLM provider, but the API key is missing.'
            ),
            'error': None if has_key else 'Anthropic API key not configured.',
        })
        return result

    base = str(endpoint or llm_cfg.get('ollama_endpoint') or llm_cfg.get('base_url') or 'http://localhost:11434').rstrip('/')
    result.update({
        'configured_model': llm_cfg.get('ollama_model', llm_cfg.get('model', 'llama3.1:8b')),
        'endpoint': base,
        'ollama_running': False,
    })

    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f'{base}/api/tags') as resp:
                if resp.status == 200:
                    result['ollama_running'] = True
                    data = await resp.json()
                    models = data.get('models', [])
                    result['available_models'] = [m.get('name', '') for m in models]

                    configured = result['configured_model']
                    for model in models:
                        name = model.get('name', '')
                        if name == configured or name.startswith(configured.split(':')[0]):
                            result['model_available'] = True
                            break

                    result['available'] = result['model_available']
                    result['status'] = 'configured' if result['model_available'] else 'degraded'
                    result['message'] = (
                        f"Ollama is running and model '{configured}' is available."
                        if result['model_available'] else
                        f"Ollama is running, but model '{configured}' is not available locally."
                    )
                else:
                    result['error'] = f'Ollama returned HTTP {resp.status}'
                    result['message'] = 'Ollama is configured but did not answer normally.'
    except Exception as exc:
        result['error'] = f'Cannot connect to Ollama: {exc}'
        result['message'] = 'Ollama is selected as the LLM provider, but the local runtime is not reachable.'

    return result


def _wants_html(request: Request) -> bool:
    """Return True when the caller is likely a browser page navigation."""
    if str(request.query_params.get('format', '')).lower() == 'json':
        return False
    accept = str(request.headers.get('accept', '')).lower()
    sec_fetch_dest = str(request.headers.get('sec-fetch-dest', '')).lower()
    return 'text/html' in accept or sec_fetch_dest == 'document'


async def _build_health_payload(request: Request):
    """Assemble the health/readiness payload used by JSON and HTML views."""
    provider = request.app.state.web_provider
    checks = {
        'analysis_manager': bool(getattr(request.app.state, 'analysis_manager', None)),
        'case_store': bool(getattr(request.app.state, 'case_store', None)),
        'tool_registry': bool(getattr(request.app.state, 'tool_registry', None)),
        'ioc_investigator': bool(getattr(request.app.state, 'ioc_investigator', None)),
        'malware_analyzer': bool(getattr(request.app.state, 'malware_analyzer', None)),
        'email_analyzer': bool(getattr(request.app.state, 'email_analyzer', None)),
        'sandbox_orchestrator': bool(getattr(request.app.state, 'sandbox_orchestrator', None)),
        'agent_loop': bool(getattr(request.app.state, 'agent_loop', None)),
    }
    critical_missing = [name for name, available in checks.items() if not available]

    llm_health_result = await _build_llm_health_result(request)
    feature_status = provider.feature_status(request.app)
    source_summary = provider.source_health_summary(request.app)
    issues = []

    llm_enabled = bool((getattr(request.app.state, 'config', {}) or {}).get('analysis', {}).get('enable_llm', True))
    sandbox_enabled = feature_status.get('sandbox', {}).get('status') not in ('disabled', '')

    if critical_missing:
        issues.extend([f"Critical component missing: {name}" for name in critical_missing])

    if llm_enabled and not llm_health_result.get('available'):
        issues.append(llm_health_result.get('error') or llm_health_result.get('message') or 'LLM provider is not ready.')

    sandbox_meta = feature_status.get('sandbox', {})
    if sandbox_enabled and sandbox_meta.get('status') == 'degraded':
        issues.append('Sandboxing is enabled, but only degraded/static-only execution paths are currently available.')

    if provider.app_mode() == 'live' and source_summary.get('ready', 0) == 0:
        issues.append('No live enrichment sources are ready.')

    if critical_missing:
        overall_status = 'unhealthy'
    elif issues:
        overall_status = 'degraded'
    else:
        overall_status = 'healthy'

    return {
        'status': overall_status,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.0.0',
        'mode': provider.app_mode(),
        'checks': checks,
        'critical_status': 'healthy' if not critical_missing else 'unhealthy',
        'capabilities': {
            'llm_runtime': llm_health_result,
            'feature_flags': feature_status,
        },
        'source_summary': source_summary,
        'issues': issues,
    }


@router.get('/health')
async def health(request: Request):
    """Health and readiness endpoint with browser-friendly HTML rendering."""
    payload = await _build_health_payload(request)

    if _wants_html(request):
        provider = request.app.state.web_provider
        templates = request.app.state.templates
        context = provider.build_template_context(
            request.app,
            request,
            health=payload,
            page_title='System Health',
            page_subtitle='Runtime readiness for AISA web, LLM, sandbox, and core services',
        )
        return templates.TemplateResponse(request, 'config_health.html', context)

    return JSONResponse(payload)


@router.get('/info')
async def info(request: Request):
    """System information."""
    provider = request.app.state.web_provider
    return {
        'app': 'AISA',
        'version': '2.0.0',
        'python': sys.version,
        'platform': platform.platform(),
        'mode': provider.app_mode(),
        'demo_enabled': provider.is_demo_mode(),
    }


@router.get('/llm-health')
async def llm_health(
    request: Request,
    endpoint: str = Query(default='http://localhost:11434'),
):
    """Provider-aware LLM health endpoint for the web UI."""
    return await _build_llm_health_result(request, endpoint=endpoint)


@router.get('/tools')
async def tool_status():
    """Check status of external analysis tools."""
    tools = {}

    # Check yara
    try:
        import yara
        tools['yara'] = {'available': True, 'version': yara.YARA_VERSION}
    except ImportError:
        tools['yara'] = {'available': False}

    # Check pefile
    try:
        import pefile
        tools['pefile'] = {'available': True}
    except ImportError:
        tools['pefile'] = {'available': False}

    # Check oletools
    try:
        import oletools
        tools['oletools'] = {'available': True}
    except ImportError:
        tools['oletools'] = {'available': False}

    # Check ssdeep
    try:
        import ssdeep
        tools['ssdeep'] = {'available': True}
    except ImportError:
        tools['ssdeep'] = {'available': False}

    return {'tools': tools}


@router.get('/settings')
async def get_settings(request: Request):
    """Return current application settings."""
    config = dict(getattr(request.app.state, 'config', {}) or {})

    # Mask API keys for security
    safe_config = dict(config)
    if 'api_keys' in safe_config:
        masked = {}
        for k, v in safe_config['api_keys'].items():
            if v and isinstance(v, str) and len(v) > 8:
                masked[k] = v[:4] + '*' * (len(v) - 8) + v[-4:]
            else:
                masked[k] = v
        safe_config['api_keys'] = masked

    if 'agent' in safe_config and isinstance(safe_config['agent'], dict):
        safe_config['agent'] = dict(safe_config['agent'])
        safe_config['agent']['default_sandbox'] = _normalize_default_sandbox(
            safe_config['agent'].get('default_sandbox', 'none')
        )

    return safe_config


@router.post('/settings')
async def save_settings(request: Request):
    """Save application settings to config.yaml."""
    from pathlib import Path

    project_root = Path(__file__).parent.parent.parent.parent
    config_file = project_root / 'config.yaml'

    body = await request.json()

    # Load existing config to preserve keys that aren't being updated
    existing = {}
    try:
        import yaml
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                existing = yaml.safe_load(f) or {}
    except ImportError:
        return {'error': 'PyYAML not installed'}, 500
    except Exception:
        pass

    # Merge sections
    for key in ('llm', 'sandbox', 'mcp_servers', 'web'):
        if key in body:
            existing[key] = body[key]

    if 'agent' in body:
        agent_updates = dict(body['agent'])
        if 'default_sandbox' in agent_updates:
            agent_updates['default_sandbox'] = _normalize_default_sandbox(agent_updates['default_sandbox'])
        if 'require_approval' in agent_updates and 'require_approval_for' not in agent_updates:
            enabled = bool(agent_updates.pop('require_approval'))
            agent_updates['require_approval_for'] = DEFAULT_APPROVAL_TOOLS if enabled else []
        existing['agent'] = {**existing.get('agent', {}), **agent_updates}

    if 'analysis' in body:
        existing['analysis'] = {**existing.get('analysis', {}), **body['analysis']}

    # Handle API keys - only update keys that are actually provided (not masked)
    if 'api_keys' in body:
        if 'api_keys' not in existing:
            existing['api_keys'] = {}
        for k, v in body['api_keys'].items():
            if v is None:
                continue
            if '*' in str(v):
                continue
            existing['api_keys'][k] = v

    try:
        import yaml
        from src.utils.config import merge_with_defaults
        from src.web.runtime_refresh import (
            apply_runtime_config_bridges,
            reconnect_startup_mcp_servers,
            refresh_runtime_components,
        )
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(existing, f, default_flow_style=False, allow_unicode=True)
        merged = apply_runtime_config_bridges(merge_with_defaults(existing))
        request.app.state.config = merged
        request.app.state.web_provider.config = merged
        if 'api_keys' in body or 'mcp_servers' in body:
            await reconnect_startup_mcp_servers(request.app)
        await refresh_runtime_components(request.app, merged)
        logger.info("[CONFIG] Settings saved to %s", config_file)
        return {'status': 'saved', 'message': 'Settings saved and applied to the live runtime.'}
    except Exception as exc:
        logger.error("[CONFIG] Failed to save settings: %s", exc)
        return {'error': str(exc)}


@router.get('/ollama-models')
async def list_ollama_models(
    endpoint: str = Query(default='http://localhost:11434'),
):
    """Proxy endpoint to list locally available Ollama models.

    Calls Ollama ``/api/tags`` and returns the model list so the frontend
    settings page can offer a dropdown selector without CORS issues.
    """
    base = endpoint.rstrip('/')
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f'{base}/api/tags') as resp:
                if resp.status != 200:
                    return {'models': [], 'error': f'Ollama returned HTTP {resp.status}'}
                data = await resp.json()
                return {'models': data.get('models', [])}
    except Exception as exc:
        logger.warning("[CONFIG] Failed to list Ollama models at %s: %s", base, exc)
        return {'models': [], 'error': str(exc)}


@router.get('/ollama-health')
async def ollama_health(
    request: Request,
    endpoint: str = Query(default='http://localhost:11434'),
):
    """Legacy alias for provider-aware LLM health diagnostics."""
    return await _build_llm_health_result(request, endpoint=endpoint)
