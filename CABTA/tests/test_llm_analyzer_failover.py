from unittest.mock import AsyncMock

import pytest

from src.integrations.llm_analyzer import LLMAnalyzer


def _llm_config():
    return {
        'api_keys': {
            'router': 'sk-router-valid-key-abcdefghijklmnopqrstuvwxyz123456',
        },
        'llm': {
            'provider': 'router',
            'model': 'cx/gpt-5.4',
            'base_url': 'http://localhost:20128/v1',
        },
    }


@pytest.mark.asyncio
async def test_llm_analyzer_uses_router_successfully():
    analyzer = LLMAnalyzer(_llm_config())

    async def _router_success(_prompt):
        analyzer._record_runtime_status(
            provider='router',
            model=analyzer._resolved_provider_model('router'),
            available=True,
            http_status=200,
        )
        return {
            'verdict': 'MALICIOUS',
            'analysis': 'IOC evidence indicates command-and-control activity.',
            'recommendations': ['Block the infrastructure immediately.'],
        }

    analyzer._call_router_api = AsyncMock(side_effect=_router_success)

    result = await analyzer.analyze_file({
        'filename': 'sample.txt',
        'file_type': 'text',
        'size_bytes': 128,
        'sha256': 'a' * 64,
        'hash_score': 90,
        'system_verdict': 'MALICIOUS',
        'composite_score': 85,
        'c2_patterns': [{'severity': 'high', 'description': 'beacon'}],
        'ip_addresses': [{'ip': '1.2.3.4', 'suspicious': True, 'is_private': False, 'reasons': ['known bad']}],
        'urls': [{'url': 'http://evil.test', 'suspicious': True, 'reasons': ['c2']}],
        'ioc_results': [{'ioc': '1.2.3.4', 'verdict': 'MALICIOUS', 'threat_score': 95}],
    })

    assert result['provider'] == 'router'
    assert result['model'] == 'cx/gpt-5.4'
    assert len(result['provider_attempts']) == 1
    assert result['provider_attempts'][0]['provider'] == 'router'


@pytest.mark.asyncio
async def test_llm_analyzer_router_rate_limit_reports_no_failover():
    analyzer = LLMAnalyzer(_llm_config())

    async def _router_failure(_prompt):
        analyzer._record_runtime_status(
            provider='router',
            model=analyzer._resolved_provider_model('router'),
            available=False,
            error='Router HTTP 429: quota exceeded',
            http_status=429,
        )
        return {'error': 'Router HTTP 429: quota exceeded'}

    analyzer._call_router_api = AsyncMock(side_effect=_router_failure)

    result = await analyzer.analyze_ioc_results('8.8.8.8', 'ip', {
        'threat_score': 5,
        'sources_checked': 1,
        'sources_flagged': 0,
        'sources': {},
    })

    assert result['provider'] == 'router'
    assert result['model'] == 'cx/gpt-5.4'
    assert result['rate_limited'] is True
    assert 'did not fall back' in result['note'].lower()


def test_llm_analyzer_router_provider_config():
    analyzer = LLMAnalyzer({
        'api_keys': {
            'router': 'sk-router-valid-key-abcdefghijklmnopqrstuvwxyz123456',
        },
        'llm': {
            'provider': 'router',
            'model': 'cx/gpt-5.4',
            'base_url': 'http://localhost:20128/v1',
        },
    })

    assert analyzer.provider == 'router'
    assert analyzer.router_api_key == 'sk-router-valid-key-abcdefghijklmnopqrstuvwxyz123456'
    assert analyzer._resolved_provider_model('router') == 'cx/gpt-5.4'
    assert analyzer.router_base_url == 'http://localhost:20128/v1'
