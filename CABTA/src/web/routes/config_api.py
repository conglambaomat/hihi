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

from src.utils.api_key_validator import is_valid_api_key

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
    {'key': 'openrouter', 'label': 'OpenRouter', 'placeholder': 'API key'},
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


def _provider_label(provider: str) -> str:
    normalized = str(provider or '').strip().lower()
    if normalized == 'openrouter':
        return 'OpenRouter'
    if not normalized:
        return 'LLM'
    return normalized.title()


def _runtime_llm_config(request: Request):
    """Return the active LLM config from app state."""
    from src.utils.config import enforce_openrouter_only

    config = enforce_openrouter_only(dict(getattr(request.app.state, 'config', {}) or {}))
    llm_cfg = config.get('llm', {}) if isinstance(config, dict) else {}
    api_keys = config.get('api_keys', {}) if isinstance(config, dict) else {}
    provider = 'openrouter'
    return llm_cfg, api_keys, provider


def _latest_runtime_llm_signal(request: Request, provider: str):
    """Return the strongest runtime signal collected by active LLM components."""
    signals = []
    for attr in ('agent_loop', 'llm_analyzer'):
        component = getattr(request.app.state, attr, None)
        signal_map = getattr(component, 'provider_runtime_statuses', None)
        if isinstance(signal_map, dict):
            mapped = signal_map.get(provider)
            if isinstance(mapped, dict) and mapped.get('available') is not None:
                signals.append(mapped)
        signal = getattr(component, 'provider_runtime_status', None)
        if not isinstance(signal, dict):
            continue
        if str(signal.get('provider') or '').strip().lower() != provider:
            continue
        if signal.get('available') is None:
            continue
        signals.append(signal)

    if not signals:
        return None

    failing = [item for item in signals if item.get('available') is False]
    if failing:
        return sorted(failing, key=lambda item: str(item.get('checked_at') or ''))[-1]

    return sorted(signals, key=lambda item: str(item.get('checked_at') or ''))[-1]


def _apply_runtime_llm_signal(result: dict, runtime_signal: dict | None) -> dict:
    """Overlay optimistic config-based health with observed runtime failures/successes."""
    if not runtime_signal:
        return result

    merged = dict(result)
    merged['last_runtime_check'] = runtime_signal.get('checked_at')

    if runtime_signal.get('available') is False:
        merged['available'] = False
        merged['model_available'] = False
        merged['status'] = 'degraded'
        merged['error'] = runtime_signal.get('error') or merged.get('error')
        merged['message'] = (
            f"{_provider_label(merged['provider'])} is configured, but the latest live runtime call failed."
        )
    elif runtime_signal.get('available') is True:
        merged['available'] = True
        merged['model_available'] = True
        merged['status'] = 'configured'

    return merged


async def _build_llm_health_result(request: Request, endpoint: str = 'http://localhost:11434'):
    """Return provider-aware LLM health diagnostics."""
    llm_cfg, api_keys, provider = _runtime_llm_config(request)
    runtime_signal = _latest_runtime_llm_signal(request, provider)
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

    has_key = is_valid_api_key(api_keys.get('openrouter')) or is_valid_api_key(llm_cfg.get('api_key'))
    result.update({
        'configured_model': llm_cfg.get('openrouter_model', llm_cfg.get('model', 'arcee-ai/trinity-large-preview:free')),
        'endpoint': str(llm_cfg.get('openrouter_endpoint', llm_cfg.get('base_url', 'https://openrouter.ai/api/v1'))).rstrip('/'),
        'available': has_key,
        'model_available': has_key,
        'status': 'configured' if has_key else 'degraded',
        'message': (
            'OpenRouter is configured for CABTA agent and analyst-assist workflows.'
            if has_key else
            'OpenRouter is selected as the LLM provider, but the API key is missing.'
        ),
        'error': None if has_key else 'OpenRouter API key not configured.',
    })
    return _apply_runtime_llm_signal(result, runtime_signal)


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
    capability_catalog = getattr(request.app.state, 'capability_catalog', None)
    daemon = getattr(request.app.state, 'headless_soc_daemon', None)
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
    capability_summary = capability_catalog.build_summary(request.app) if capability_catalog else {}
    verdict_authority = (
        capability_catalog.build_catalog(request.app).get('verdict_authority', {})
        if capability_catalog else {}
    )
    daemon_status = daemon.build_status(request.app) if daemon else {"enabled": False, "schedule_count": 0}
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
        'verdict_authority': verdict_authority,
        'capabilities': {
            'llm_runtime': llm_health_result,
            'feature_flags': feature_status,
            'orchestration': capability_summary,
            'daemon': daemon_status,
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
            page_subtitle='Runtime readiness for CABTA web, LLM, sandbox, and core services',
        )
        return templates.TemplateResponse(request, 'config_health.html', context)

    return JSONResponse(payload)


@router.get('/info')
async def info(request: Request):
    """System information."""
    provider = request.app.state.web_provider
    capability_catalog = getattr(request.app.state, 'capability_catalog', None)
    capability_summary = capability_catalog.build_summary(request.app) if capability_catalog else {}
    return {
        'app': 'CABTA',
        'version': '2.0.0',
        'python': sys.version,
        'platform': platform.platform(),
        'mode': provider.app_mode(),
        'demo_enabled': provider.is_demo_mode(),
        'verdict_authority_owner': capability_summary.get('verdict_authority_owner', 'cabta_scoring'),
        'agent_profile_count': capability_summary.get('agent_profile_count', 0),
        'workflow_count': capability_summary.get('workflow_count', 0),
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

    config_file = Path(
        getattr(request.app.state, 'config_file', Path(__file__).parent.parent.parent.parent / 'config.yaml')
    )

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
        from src.utils.config import enforce_openrouter_only, merge_with_defaults
        from src.utils.config_history import snapshot_config
        from src.web.runtime_refresh import (
            apply_runtime_config_bridges,
            reconnect_startup_mcp_servers,
            refresh_runtime_components,
        )
        pre_save_snapshot = None
        if config_file.exists():
            try:
                pre_save_snapshot = snapshot_config(config_file, reason='pre-web-settings-save')
            except Exception as history_exc:
                logger.warning("[CONFIG] Pre-save config snapshot failed: %s", history_exc)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        persisted = enforce_openrouter_only(existing)
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(persisted, f, default_flow_style=False, allow_unicode=True)
        post_save_snapshot = None
        try:
            post_save_snapshot = snapshot_config(config_file, reason='post-web-settings-save')
        except Exception as history_exc:
            logger.warning("[CONFIG] Post-save config snapshot failed: %s", history_exc)
        merged = apply_runtime_config_bridges(merge_with_defaults(persisted))
        runtime_merged = apply_runtime_config_bridges(
            merge_with_defaults(existing, normalize_llm=False),
            normalize_llm=False,
        )
        request.app.state.config = runtime_merged
        request.app.state.web_provider.config = runtime_merged
        if 'api_keys' in body or 'mcp_servers' in body:
            await reconnect_startup_mcp_servers(request.app)
        await refresh_runtime_components(request.app, runtime_merged)
        logger.info("[CONFIG] Settings saved to %s", config_file)
        return {
            'status': 'saved',
            'message': 'Settings saved and applied to the live runtime.',
            'config_history': {
                'before': pre_save_snapshot,
                'after': post_save_snapshot,
            },
        }
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
