"""
Author: Ugur Ates
Configuration loader for AISA.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from .runtime_paths import legacy_home, runtime_cache_dir, runtime_home

logger = logging.getLogger(__name__)

ROUTER_PROVIDER = 'router'
ROUTER_DEFAULT_MODEL = 'cx/gpt-5.4'
ROUTER_DEFAULT_BASE_URL = 'http://localhost:20128/v1'


def enforce_router_only(config: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize config so AISA uses one OpenAI-compatible router runtime only."""
    normalized = dict(config or {})
    llm = dict(normalized.get('llm', {}) or {})
    api_keys = dict(normalized.get('api_keys', {}) or {})

    legacy_api_key = (
        llm.get('api_key')
        or api_keys.get('router')
        or api_keys.get('openrouter')
        or api_keys.get('openai')
        or ''
    )
    legacy_model = llm.get('model') or llm.get('openrouter_model') or llm.get('openai_model') or ROUTER_DEFAULT_MODEL
    legacy_base_url = llm.get('base_url') or llm.get('router_base_url') or ROUTER_DEFAULT_BASE_URL
    legacy_timeout_seconds = llm.get('timeout_seconds') or llm.get('request_timeout') or llm.get('router_timeout_seconds')

    llm.clear()
    llm.update({
        'provider': ROUTER_PROVIDER,
        'base_url': str(legacy_base_url or ROUTER_DEFAULT_BASE_URL).rstrip('/'),
        'model': str(legacy_model or ROUTER_DEFAULT_MODEL).strip() or ROUTER_DEFAULT_MODEL,
        'api_key': str(legacy_api_key or '').strip(),
    })
    if legacy_timeout_seconds is not None:
        llm['timeout_seconds'] = legacy_timeout_seconds

    api_keys['router'] = llm['api_key']

    normalized['llm'] = llm
    normalized['api_keys'] = api_keys
    return normalized




def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config.yaml file. If None, searches standard locations.
    
    Returns:
        Dict containing configuration
    
    Example:
        >>> config = load_config()
        >>> vt_key = config['api_keys']['virustotal']
    """
    # Standard config locations
    search_paths = [
        config_path,
        os.environ.get('BTA_CONFIG'),
        'config.yaml',
        runtime_home() / 'config.yaml',
        legacy_home() / 'config.yaml',
        Path(__file__).parent.parent.parent / 'config.yaml'
    ]
    
    config_file = None
    for path in search_paths:
        if path and Path(path).exists():
            config_file = Path(path)
            logger.info(f"[CONFIG] Loading from: {config_file}")
            break
    
    if not config_file:
        logger.warning("[CONFIG] No config file found, using defaults")
        return get_default_config()
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return merge_with_defaults(config)
    except Exception as e:
        logger.error(f"[CONFIG] Failed to load config: {e}")
        return get_default_config()
def get_default_config() -> Dict[str, Any]:
    """
    Get default configuration with environment variable fallbacks.
    
    Returns:
        Default configuration dict
    """
    return {
        'api_keys': {
            # Core sources
            'virustotal': os.environ.get('VIRUSTOTAL_API_KEY', ''),
            'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY', ''),
            'shodan': os.environ.get('SHODAN_API_KEY', ''),
            'alienvault': os.environ.get('ALIENVAULT_API_KEY', ''),
            
            # Extended sources
            'greynoise': os.environ.get('GREYNOISE_API_KEY', ''),
            'censys_id': os.environ.get('CENSYS_API_ID', ''),
            'censys_secret': os.environ.get('CENSYS_API_SECRET', ''),
            'pulsedive': os.environ.get('PULSEDIVE_API_KEY', ''),
            'criminalip': os.environ.get('CRIMINALIP_API_KEY', ''),
            'ipqualityscore': os.environ.get('IPQS_API_KEY', ''),
            'phishtank': os.environ.get('PHISHTANK_API_KEY', ''),
            
            # Sandbox sources
            'hybridanalysis': os.environ.get('HYBRID_API_KEY', ''),
            'anyrun': os.environ.get('ANYRUN_API_KEY', ''),
            'triage': os.environ.get('TRIAGE_API_KEY', ''),
            'threatzone': os.environ.get('THREATZONE_API_KEY', ''),
            'joesandbox': os.environ.get('JOESANDBOX_API_KEY', ''),
            
            # Legacy
            'ip2proxy': os.environ.get('IP2PROXY_API_KEY', ''),
            
            # LLM router (optional)
            'router': (
                os.environ.get('LLM_API_KEY', '')
                or os.environ.get('ROUTER_API_KEY', '')
                or os.environ.get('OPENAI_API_KEY', '')
                or os.environ.get('OPENROUTER_API_KEY', '')
            ),
        },
        'agent': {
            'max_steps': 1000,
            'auto_enrich_timeout_seconds': 12,
            'chat_tool_cap': 14,
            'chat_prompt_findings_limit': 5,
            'chat_auto_enrich_limit': 1,
            'chat_response_timeout_seconds': 120,
            'context': {
                'enabled': True,
                'context_window_tokens': 32000,
                'reserved_output_tokens': 4096,
                'safety_margin_tokens': 1024,
                'hard_prompt_budget_ratio': 0.92,
                'compaction_threshold_ratio': 0.85,
                'max_context_pack_bytes': 200000,
                'max_ledger_items': 120,
                'section_budgets': {
                    'system_rules': 0.10,
                    'goal': 0.06,
                    'reasoning': 0.20,
                    'evidence': 0.24,
                    'entities': 0.10,
                    'hypotheses': 0.12,
                    'coverage': 0.08,
                    'tools': 0.06,
                    'workflow': 0.04,
                },
            },
        },
        'rate_limits': {
            'virustotal': {'requests_per_minute': 4},
            'abuseipdb': {'requests_per_day': 1000},
            'shodan': {'requests_per_month': 100},
            'concurrent_requests': 5
        },
        'timeouts': {
            'api_timeout': 30,
            'sandbox_timeout': 300
        },
        'scoring': {
            'clean_threshold': 5,
            'low_risk_threshold': 30,
            'suspicious_threshold': 60,
            'malicious_threshold': 80
        },
        'analysis': {
            'max_archive_depth': 3,
            'max_file_size_mb': 100,
            'enable_sandboxes': False,
            'enable_llm': True,
            'llm_timeout_seconds': 25,
            'text_max_scan_mb': 3,
        },
        'llm': {
            'provider': ROUTER_PROVIDER,
            'base_url': ROUTER_DEFAULT_BASE_URL,
            'model': ROUTER_DEFAULT_MODEL,
            'timeout_seconds': 120,
            'api_key': (
                os.environ.get('LLM_API_KEY', '')
                or os.environ.get('ROUTER_API_KEY', '')
                or os.environ.get('OPENAI_API_KEY', '')
                or os.environ.get('OPENROUTER_API_KEY', '')
            ),
        },
        'output': {
            'report_format': 'html',
            'save_reports': True,
            'reports_dir': './reports'
        },
        'cache': {
            'enabled': True,
            'db_dir': str(runtime_cache_dir()),
            'ioc_ttl_hours': 24,
            'analysis_max_age_days': 30,
        },
        'web': {
            'host': '0.0.0.0',
            'port': 8080,
            'debug': False,
            'max_upload_mb': 100,
            'demo_mode': {
                'enabled': False,
                'dataset': 'default',
            },
        },
        'log_hunting': {
            'max_window_hours': 24 * 7,
            'max_results': 200,
            'max_queries_per_hunt': 3,
            'max_retry_attempts': 3,
            'max_attempts_per_gap': 2,
            'max_attempts_per_objective': 3,
            'max_attempts_per_session': 6,
            'llm_query_assist_enabled': False,
            'llm_query_assist_max_candidates': 3,
            'llm_query_assist_require_validation': True,
        },
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    }
def merge_with_defaults(config: Dict[str, Any], *, normalize_llm: bool = True) -> Dict[str, Any]:
    """
    Merge user config with defaults.
    
    Args:
        config: User configuration
    
    Returns:
        Merged configuration
    """
    defaults = get_default_config()
    
    def deep_merge(base: Dict, override: Dict) -> Dict:
        """Recursively merge two dicts."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    merged = deep_merge(defaults, config)
    return enforce_router_only(merged) if normalize_llm else merged
def get_api_key(config: Dict[str, Any], service: str) -> Optional[str]:
    """
    Get API key for a service.
    
    Args:
        config: Configuration dict
        service: Service name (virustotal, abuseipdb, etc.)
    
    Returns:
        API key or None if not configured
    """
    key = config.get('api_keys', {}).get(service, '')
    return key if key else None
def is_service_enabled(config: Dict[str, Any], service: str) -> bool:
    """
    Check if a service is enabled (has valid API key).
    
    Args:
        config: Configuration dict
        service: Service name
    
    Returns:
        True if service has API key configured
    """
    key = get_api_key(config, service)
    return key is not None and len(key) > 0
